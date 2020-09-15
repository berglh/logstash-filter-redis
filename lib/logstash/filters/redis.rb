# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# A general search and replace tool which queries replacement values from a redis instance.
#
# This is actually a redis version of a translate plugin. <https://www.elastic.co/guide/en/logstash/current/plugins-filters-translate.html>
#
# Operationally, if the event field specified in the "field" configuration
# matches the EXACT contents of a redis key, the field's value will be substituted
# with the matched key's value from the redis GET <key> command.
# 
# By default, the redis filter will replace the contents of the 
# matching event field (in-place). However, by using the "destination"
# configuration item, you may also specify a target event field to
# populate with the new translated value.
# 
# Alternatively, for simple string search and replacements for just a few values
# you might consider using the gsub function of the mutate filter.

class LogStash::Filters::Redis < LogStash::Filters::Base
  config_name "redis"

  # The hostname of your redis server.
  config :host, :validate => :string, :default => "127.0.0.1"

  # The port to connect on.
  config :port, :validate => :number, :default => 6379

  # Password to authenticate with. There is no authentication by default.
  config :password, :validate => :password

  # The redis database number.
  config :db, :validate => :number, :default => 0
  
  # The name of the event field containing the value to be used as the KEY in
  # either GET or SET operations.
  # 
  # If this field is an array, only the first value will be used.
  config :key, :validate => :string, :required => true

  # The redis action to perform.
  config :action, :validate => [ "GET", "SET" ], :required => true

  # The format of the value returned by the GET method. JSON will try to decode JSON.
  config :format, :validate => [ "string", "json" ], :required => false, :default => "string"

  # Set an optional TTL in seconds for the SET action to have values written to redis
  # automatically expire.
  config :ttl, :validate => :number, :required => false, :default => 0

  # The value to set in the redis key. Value is a string. `%{fieldname}` substitutions are
  # allowed in the values. Only used for "SET".
  config :value, :validate => :string

  # If the destination (or target) field already exists, this configuration item specifies
  # whether the filter should skip translation (default) or overwrite the target field
  # value with the new translation value.
  config :override, :validate => :boolean, :default => false

  # The destination field you wish to populate with the translated code. The default
  # is a field named "redis". Set this to the same value as source if you want
  # to do a substitution, in this case filter will allways succeed. This will clobber
  # the old value of the source field! 
  config :destination, :validate => :string, :default => "redis"

  # In case no translation occurs in the event (no matches), this will add a default
  # translation string, which will always populate "field", if the match failed.
  #
  # For example, if we have configured `fallback => "no match"`, using this dictionary:
  #
  #     foo: bar
  #
  # Then, if logstash received an event with the field `foo` set to "bar", the destination
  # field would be set to "bar". However, if logstash received an event with `foo` set to "nope",
  # then the destination field would still be populated, but with the value of "no match".
  config :fallback, :validate => :string

  # Connection timeout in seconds to Redis server
  config :timeout, :validate => :number, :default => 1

  # Number of times to retry a failed connection to Redis server
  config :retries, :validate => :number, :default => 3

  # Number of events to let pass before attempting a reconnect
  # This will silently fail and pass through this number of events before trying to reconnect
  # Being kinder on agressive reconnects every event sounds like a good idea
  config :events_before_retry, :validate => :number, :default => 10000

  public
  def register
    require 'redis'
    require 'json'
    @redis = nil
    @reconnect_timer = 0
    @connected = false
    connect
    @logger.warn("filter-redis: config", :config => @redis.connection, :connected => @connected, :reconnect_timer => @reconnect_timer)
  end # def register

  private
  def connect
    @connected = false
    @retries.times do
      @logger.debug("filter-redis: connecting to redis server")
      @redis ||= Redis.new(
        :host => @host,
        :port => @port,
        :timeout => @timeout,
        :db => @db,
        :password => @password.nil? ? nil : @password.value
      )
      begin
        result = @redis.ping
        if @redis.connected? && result == "PONG"
          @connected = true
          break
        else
          @logger.debug("filter-redis: connection failed, retrying")
        end
      rescue ::Redis::BaseError => e
        @logger.warn("filter-redis: problem establishing redis connection", :exception => e)
      end
    end
    return
  end #def connect

  private
  def get_value(key)
    success = false
    value = ''
    begin
      value = @redis.get(key)
      if !value.nil?
        success = true
        return success, value
      else
        @logger.warn("filter-redis: unable to find key in redis", :key => key)
        return success, nil
      end
    rescue ::Redis::BaseError => e
      @logger.warn("filter-redis: problem getting redis key, connection problem", :key => key, :exception => e)
      return success, nil
    end
  end #def get_value

  private
  def set_value(key, value)
    success = false
    begin
      @redis.set(key, value)
      if @ttl != 0
        begin
          @redis.expire(key, @ttl)
        end
      end
      if value
        success = true
        return success
      end
    rescue ::Redis::BaseError => e
      @logger.warn("filter-redis: problem setting redis key, connection problem?", :key => key, :value => value, :exception => e)
      return success
    end
    @logger.warn("filter-redis: redis problem setting key, connection problem?", :key => key, :value => value)
    return success
  end #def set_value


  public
  def filter(event)
    return unless event.include?(@key)

    if @reconnect_timer != 0
      if @reconnect_timer = @events_before_retry
        @logger.warn("filter-redis: timer threshold hit, time to reconnect", :reconnect_timer => @reconnect_timer)
        @reconnect_timer = 0
        connect
      end
    elsif @reconnect_timer == 0 && !@redis.connected?
      # connect
      @logger.warn("filter-redis: reconnect_timer", :reconnect_timer => @reconnect_timer)
      connect
    end

    if @redis.connected?
      # GET
      if @action == "GET"
        return if event.include?(@destination) and not @override

        success = nil
        key = event.get(@key).is_a?(Array) ? event.get(@key).first.to_s : event.get(@key).to_s
        success, value = get_value(key)
        if success && value != '' && !value.nil?          
          begin
            if @format == "string"
              event.set(@destination, value)
            elsif @format == "json"
              event.set(@destination, JSON.parse(value))
            end
            filter_matched(event)
          rescue JSON::ParserError => e
            event.set(@destination, value)
            filter_matched(event)
          end
        elsif @fallback
          event.set(@destination, @fallback)
          filter_matched(event)
        else
          @logger.debug("filter-redis: redis didn't find a match for GET", :key => key)
        end
      # SET
      elsif @action == "SET"
        return unless @value
      
        success = nil
        key = event.get(@key).is_a?(Array) ? event.get(@key).first.to_s : event.get(@key).to_s
        value = event.sprintf(@value)
        success = set_value(key, value)
        if !success
          @logger.debug("filter-redis: redis wasn't able to SET key value pair", :key => key, :value => value)
        end
      end # end SET & GET actions
    else
      @logger.warn("filter-redis: redis connection offline, incrementing timer", :reconnect_timer => @reconnect_timer)
      @reconnect_timer += 1
    end # if @ connected?
  end # def filter

end # class LogStash::Filters::Redis
