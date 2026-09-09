#!/usr/bin/env ruby
# Static inventory only. Enumeration and valid YAML do not prove API behavior.
require 'yaml'
require 'json'
require 'digest'

METHODS = %w[get put post delete patch head options].freeze
ROOT = File.expand_path('../..', __dir__)
FILES = %w[api/swagger.yml api/swagger-extras.yml].freeze

def pointer(parts)
  '/' + parts.map { |p| p.to_s.gsub('~', '~0').gsub('/', '~1') }.join('/')
end

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
    node.children.each_with_index { |child, i| check_yaml(child, "#{path}/#{i}", errors) }
  end
end

def walk(value, parts = [], &block)
  if value.is_a?(Hash)
    yield(value, parts)
    value.each { |key, child| walk(child, parts + [key], &block) }
  elsif value.is_a?(Array)
    value.each_with_index { |child, i| walk(child, parts + [i], &block) }
  end
end

documents = {}
errors = []
FILES.each do |file|
  bytes = File.read(File.join(ROOT, file))
  check_yaml(Psych.parse_stream(bytes), file, errors)
  documents[file] = YAML.safe_load(bytes, permitted_classes: [], aliases: false)
end

items = []
references = []
documents.each do |file, spec|
  walk(spec) do |node, parts|
    kind = if parts.length == 3 && parts[0] == 'paths' && METHODS.include?(parts[2])
             'operation'
           elsif parts.length == 2 && parts[0] == 'definitions'
             'definition'
           elsif parts[-2] == 'properties'
             'property'
           elsif parts[-2] == 'parameters'
             'parameter'
           elsif parts[-2] == 'responses'
             'response'
           elsif parts[-2] == 'securityDefinitions'
             'security_scheme'
           end
    if kind
      items << {'id' => file + '#' + pointer(parts), 'kind' => kind,
                'hasDescription' => !node.fetch('description', '').strip.empty?,
                'reviewStatus' => 'UNREVIEWED'}
    end
    next unless node['$ref']
    ref = node['$ref']
    references << {'from' => file + '#' + pointer(parts), 'ref' => ref}
    resource, fragment = ref.split('#', 2)
    target_file = resource.empty? ? file : File.join(File.dirname(file), resource)
    target = documents[target_file]
    unless target && fragment && fragment.start_with?('/')
      errors << "unsupported or unavailable reference #{file}: #{ref}"
      next
    end
    fragment.split('/')[1..-1].each do |encoded|
      key = encoded.gsub('~1', '/').gsub('~0', '~')
      target = if target.is_a?(Hash)
                 target[key]
               elsif target.is_a?(Array) && key.match?(/\A\d+\z/)
                 target[key.to_i]
               end
    end
    errors << "unresolved reference #{file}: #{ref}" if target.nil?
  end
end

result = {
  'schemaVersion' => 1,
  'status' => 'IN_PROGRESS',
  'evidenceClass' => 'static-inventory-not-behavior-verification',
  'baseline' => 'codex/ai-multitier-cicd f8e6ace2 plus WIP; see review.md',
  'documents' => FILES.map do |file|
    {'file' => file, 'sha256' => Digest::SHA256.file(File.join(ROOT, file)).hexdigest,
     'paths' => documents[file].fetch('paths', {}).length,
     'counts' => items.select { |i| i['id'].start_with?(file + '#') }
                      .group_by { |i| i['kind'] }.transform_values(&:length)}
  end,
  'errors' => errors,
  'items' => items,
  'references' => references
}

# Validate references/grammar of advisory relationships, not their runtime truth.
relations = documents['api/swagger.yml']['x-loxilb-contract-relations']
if relations
  errors << 'unsupported relationship version' unless relations['version'] == 1
  scope = relations['scope'].to_s.split('/').last
  schema = documents['api/swagger.yml'].fetch('definitions', {})[scope]
  errors << 'relationship scope does not resolve' unless schema
  seen = {}
  relations.fetch('rules', []).each do |rule|
    id = rule['id']
    errors << "missing/duplicate relationship id #{id}" if !id || seen[id]
    seen[id] = true
    kind = rule['kind']
    errors << "unknown relationship kind #{kind}" unless %w[requires filtered-count sum-bound].include?(kind)
    errors << "missing relationship evidence #{id}" if rule.fetch('evidence', '').empty?
    errors << "unexpected relationship enforcement #{id}" unless rule['enforcement'] == 'server-static'
    predicates = [rule['when']] + rule.fetch('require', [])
    predicates.each do |pred|
      unless pred.is_a?(Hash) && %w[in greater-than nonempty-string].include?(pred['operator'])
        errors << "invalid predicate #{id}"
        next
      end
      errors << "missing predicate values #{id}" if pred['operator'] == 'in' && !pred['values'].is_a?(Array)
      errors << "missing numeric comparison #{id}" if pred['operator'] == 'greater-than' && !pred['value'].is_a?(Numeric)
    end
    fields = predicates.compact.map { |p| p['field'] } + rule.fetch('terms', []).map { |p| p['field'] }
    fields << rule['array'] if rule['array']
    fields.each do |field|
      target = schema
      field.to_s.split('/')[1..-1].to_a.each do |key|
        target = target.is_a?(Hash) ? target.fetch('properties', {})[key] : nil
      end
      errors << "relationship field does not resolve #{id}: #{field}" unless target && field.to_s.start_with?('/')
    end
    if kind == 'filtered-count'
      target = schema
      rule.fetch('array', '').split('/')[1..-1].to_a.each { |key| target = target.fetch('properties', {})[key] if target }
      rule.fetch('counts', []).each do |count|
        name = count['field'].to_s.sub(%r{\A/}, '')
        errors << "filtered-count field does not resolve #{id}: #{name}" unless target && target.fetch('items', {}).fetch('properties', {}).key?(name)
      end
    end
  end
end

if ARGV.include?('--write')
  # Generated inventory only; never modifies specifications or audit verdicts.
  File.write(File.join(__dir__, 'inventory.json'), JSON.pretty_generate(result) + "\n")
end
if ARGV.include?('--summary') || ARGV.include?('--write')
  result = result.reject { |key, _| %w[items references].include?(key) }
end
puts JSON.pretty_generate(result)
exit(errors.empty? ? 0 : 1)
