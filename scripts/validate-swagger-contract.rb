#!/usr/bin/env ruby
# Validate public Swagger structure and project relationship metadata.
require 'yaml'

ROOT = File.expand_path('..', __dir__)
FILES = %w[api/swagger.yml api/swagger-extras.yml].freeze
PREDICATES = %w[in greater-than nonempty-string].freeze
RELATION_KINDS = %w[requires filtered-count sum-bound conditional-join-byte-bound].freeze

def check_yaml(node, path, errors)
  if node.is_a?(Psych::Nodes::Mapping)
    seen = {}
    node.children.each_slice(2) do |key, value|
      name = key.value
      errors << "duplicate YAML key #{path}/#{name} at line #{key.start_line + 1}" if seen[name]
      seen[name] = true
      check_yaml(value, "#{path}/#{name}", errors)
    end
  elsif node.respond_to?(:children) && node.children
    node.children.each_with_index { |child, index| check_yaml(child, "#{path}/#{index}", errors) }
  end
end

def walk(value, &block)
  if value.is_a?(Hash)
    yield value
    value.each_value { |child| walk(child, &block) }
  elsif value.is_a?(Array)
    value.each { |child| walk(child, &block) }
  end
end

def resolve_pointer(root, pointer)
  return nil unless pointer.is_a?(String) && pointer.start_with?('/')
  pointer.split('/')[1..].reduce(root) do |node, encoded|
    key = encoded.gsub('~1', '/').gsub('~0', '~')
    node.is_a?(Hash) ? node[key] : nil
  end
end

def resolve_schema_field(schema, pointer)
  return nil unless pointer.is_a?(String) && pointer.start_with?('/')
  pointer.split('/')[1..].reduce(schema) do |node, encoded|
    key = encoded.gsub('~1', '/').gsub('~0', '~')
    node.is_a?(Hash) ? node.fetch('properties', {})[key] : nil
  end
end

errors = []
documents = {}

FILES.each do |file|
  bytes = File.read(File.join(ROOT, file))
  check_yaml(Psych.parse_stream(bytes), file, errors)
  documents[file] = YAML.safe_load(bytes, permitted_classes: [], aliases: false)
end

documents.each do |file, spec|
  walk(spec) do |node|
    next unless node['$ref']
    resource, fragment = node['$ref'].split('#', 2)
    target_file = resource.empty? ? file : File.join(File.dirname(file), resource)
    target = documents[target_file]
    target = resolve_pointer(target, fragment) if target && fragment
    errors << "unresolved reference #{file}: #{node['$ref']}" if target.nil?
  end
end

spec = documents.fetch('api/swagger.yml')
relations = spec['x-loxilb-contract-relations']
if relations.nil?
  errors << 'missing x-loxilb-contract-relations'
else
  errors << "unsupported relationship version #{relations['version'].inspect}" unless relations['version'] == 1
  scope = relations['scope'].to_s.sub(/\A#/, '')
  schema = resolve_pointer(spec, scope)
  errors << "unresolved relationship scope #{relations['scope'].inspect}" if schema.nil?

  ids = {}
  Array(relations['rules']).each do |rule|
    id = rule['id']
    if !id.is_a?(String) || id.empty? || ids[id]
      errors << "missing or duplicate relationship id #{id.inspect}"
      next
    end
    ids[id] = true
    kind = rule['kind']
    errors << "unknown relationship kind #{kind.inspect} for #{id}" unless RELATION_KINDS.include?(kind)
    errors << "missing message for #{id}" unless rule['message'].is_a?(String) && !rule['message'].empty?
    errors << "missing evidence for #{id}" unless rule['evidence'].is_a?(String) && !rule['evidence'].empty?
    errors << "invalid enforcement for #{id}" unless rule['enforcement'] == 'server-static'
    next if schema.nil?

    predicates = []
    predicates << rule['when'] if rule.key?('when')
    predicates.concat(Array(rule['require']))
    predicates.each do |predicate|
      unless predicate.is_a?(Hash) && PREDICATES.include?(predicate['operator'])
        errors << "invalid predicate for #{id}"
        next
      end
      errors << "unresolved field #{predicate['field'].inspect} for #{id}" if resolve_schema_field(schema, predicate['field']).nil?
      errors << "missing values for #{id}" if predicate['operator'] == 'in' && !predicate['values'].is_a?(Array)
      errors << "missing numeric value for #{id}" if predicate['operator'] == 'greater-than' && !predicate['value'].is_a?(Numeric)
    end

    case kind
    when 'requires'
      errors << "missing when for #{id}" unless rule['when'].is_a?(Hash)
      errors << "missing require list for #{id}" if Array(rule['require']).empty?
    when 'filtered-count'
      array_schema = resolve_schema_field(schema, rule['array'])
      errors << "unresolved array #{rule['array'].inspect} for #{id}" unless array_schema && array_schema['type'] == 'array'
      Array(rule['counts']).each do |count|
        item_field = resolve_schema_field(array_schema.fetch('items', {}), count['field']) if array_schema
        errors << "unresolved count field #{count['field'].inspect} for #{id}" if item_field.nil?
        errors << "invalid minimum for #{id}" unless count['minimum'].is_a?(Numeric)
      end
      errors << "missing counts for #{id}" if Array(rule['counts']).empty?
    when 'sum-bound'
      Array(rule['terms']).each do |term|
        errors << "unresolved term #{term['field'].inspect} for #{id}" if resolve_schema_field(schema, term['field']).nil?
      end
      errors << "missing terms for #{id}" if Array(rule['terms']).empty?
      errors << "invalid maximum for #{id}" unless rule['maximum'].is_a?(Numeric)
    when 'conditional-join-byte-bound'
      fields = rule['fields']
      if !fields.is_a?(Hash) || fields.empty?
        errors << "missing fields for #{id}"
      else
        fields.each_value do |pointer|
          errors << "unresolved joined field #{pointer.inspect} for #{id}" if resolve_schema_field(schema, pointer).nil?
        end
      end
      encodings = rule['encodings']
      errors << "missing encodings for #{id}" unless encodings.is_a?(Array) && !encodings.empty?
      errors << "invalid maximum for #{id}" unless rule['maximum'].is_a?(Numeric)
      errors << "invalid unit for #{id}" unless rule['unit'] == 'utf8-bytes'
    end
  end
end

if errors.empty?
  puts "OK: validated #{FILES.length} Swagger documents and #{relations.fetch('rules', []).length} relationship rules"
  exit 0
end

errors.each { |error| warn "ERROR: #{error}" }
exit 1
