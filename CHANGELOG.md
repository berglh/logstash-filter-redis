
# 0.4.0
  - Added the SET feature to write values to redis
  - Added "action" parameter to specify SET or GET 
  - Added "ttl" parameter for setting expire attributes on SET action
  - Added "value" field to be used as value for SET action thats supports %{field} substitution

# 0.3.0
  - Added support for logstash 5.0.0

# 0.2.0
  - Removed data store feature
  - Renamed configuration option "key" into "field" to match configuration of translate plugin
  - Changed main functionality and configuration similar to translate filter (logstash-plugins/logstash-filter-translate)
  - Added field, destination and override configuration options and their handling from logstash-plugins/logstash-filter-translate/blob/master/lib/logstash/filters/translate.rb

# 0.1.0
  - forked from meulop/logstash-filter-redis
