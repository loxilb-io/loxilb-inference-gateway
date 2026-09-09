#!/usr/bin/env ruby
# Verify the main embedded document; this is not a runtime API test.
require 'yaml'
require 'json'

root = File.expand_path('../..', __dir__)
spec = YAML.safe_load(File.read(File.join(root, 'api/swagger.yml')), aliases: false)
path = ARGV[0] || File.join(root, 'api/restapi/embedded_spec.go')
source = File.read(path)
start = 'SwaggerJSON = json.RawMessage([]byte(`'
payload = source.split(start, 2)[1]&.split('`))', 2)&.first
abort 'FAIL: embedded SwaggerJSON assignment not found' unless payload
# go-swagger escapes backticks by concatenating a quoted backtick.
payload = payload.gsub('` + "`" + `', '`')
begin
  embedded = JSON.parse(payload)
rescue JSON::ParserError
  abort 'FAIL: unsupported embedded string encoding or invalid JSON'
end
# go-openapi serializes optional parameter `required: false` by omission.
# Normalize only that documented default, not descriptions, bounds or extensions.
normalize = lambda do |value|
  case value
  when Hash
    value.reject { |key, item| key == 'required' && item == false && value.key?('in') }
         .transform_keys(&:to_s)
         .transform_values { |item| normalize.call(item) }
  when Array
    value.map { |item| normalize.call(item) }
  else
    value
  end
end
spec = normalize.call(spec)
embedded = normalize.call(embedded)
unless spec == embedded
  differences = []
  compare = lambda do |left, right, pointer|
    next if left == right || differences.length >= 100
    if left.is_a?(Hash) && right.is_a?(Hash)
      (left.keys | right.keys).each { |key| compare.call(left[key], right[key], "#{pointer}/#{key}") }
    elsif left.is_a?(Array) && right.is_a?(Array) && left.length == right.length
      left.each_index { |index| compare.call(left[index], right[index], "#{pointer}/#{index}") }
    else
      differences << "#{pointer}: #{left.inspect[0, 100]} != #{right.inspect[0, 100]}"
    end
  end
  compare.call(spec, embedded, '')
  warn differences.join("\n")
  abort 'FAIL: embedded SwaggerJSON differs from api/swagger.yml'
end
puts 'PASS: embedded SwaggerJSON matches the main spec (optional required:false normalized)'
