#!/usr/bin/env ruby
# frozen_string_literal: true

# Static coverage check for ESO manifests that use this webhook provider.
#
# The check is intentionally local and read-only: it parses rendered Kubernetes
# YAML and verifies that every ExternalSecret selector is covered by the
# provider selector policy visible in the same manifest set.
# It never reads Kubernetes Secret data.

require "date"
require "digest"
require "optparse"
require "psych"
require "set"
require "yaml"

options = {
  show_keys: false,
  allow_empty: false,
  allowed_keys: Set.new,
  allowed_prefixes: [],
  providers: Set.new,
  stores: Set.new,
  cluster_stores: Set.new
}

SELECTOR_POLICY_ENV_NAMES = Set[
  "BWESO_ALLOWED_KEYS",
  "BWESO_ALLOWED_KEY_PREFIXES",
  "BWESO_ALLOWED_KEYS_FILE",
  "BWESO_ALLOWED_KEY_PREFIXES_FILE",
  "BWESO_ALLOW_ALL_SELECTORS"
].freeze
YAML_STRING_TAG = "tag:yaml.org,2002:str"

parser = OptionParser.new do |opts|
  opts.banner = "Usage: scripts/eso-policy-coverage.rb [options] <manifest.yaml|dir>..."
  opts.on("--provider NAMESPACE/NAME", "Read policy only from this provider Deployment; repeatable.") do |value|
    options[:providers].add(value)
  end
  opts.on("--store NAMESPACE/NAME", "Check only ExternalSecrets using this SecretStore; repeatable.") do |value|
    options[:stores].add(value)
  end
  opts.on("--cluster-store NAME", "Check only ExternalSecrets using this ClusterSecretStore; repeatable.") do |value|
    options[:cluster_stores].add(value)
  end
  opts.on("--allowed-key KEY", "Add an exact allowed selector key.") do |value|
    options[:allowed_keys].add(value)
  end
  opts.on("--allowed-prefix PREFIX", "Add an allowed selector key prefix.") do |value|
    options[:allowed_prefixes] << value
  end
  opts.on("--show-keys", "Print raw selector keys in findings.") do
    options[:show_keys] = true
  end
  opts.on(
    "--allow-empty",
    "Allow zero selected ExternalSecret remote keys and zero provider policy deployments."
  ) do
    options[:allow_empty] = true
  end
end

paths = begin
  parser.parse(ARGV)
rescue OptionParser::ParseError => e
  warn e.message
  warn parser.banner
  exit 2
end
if paths.empty?
  warn parser.banner
  exit 2
end

def manifest_files(paths)
  paths.flat_map do |path|
    if path == "-"
      path
    elsif File.directory?(path)
      Dir.glob(File.join(path, "**", "*.{yaml,yml}"))
    elsif File.file?(path)
      path
    else
      warn "#{path}: file or directory not found"
      exit 2
    end
  end.uniq.sort
end

def each_document(files)
  files.each do |file|
    safe_load_stream(file).each do |document|
      expand_kubernetes_list(document).each do |expanded, index|
        next unless expanded.is_a?(Hash)

        source = index.nil? ? file : "#{file}#items[#{index}]"
        yield source, expanded
      end
    end
  rescue Psych::SyntaxError => e
    warn "#{file}: invalid YAML: #{e.message}"
    exit 2
  rescue Psych::Exception => e
    warn "#{file}: unsupported or unsafe YAML: #{e.message}"
    exit 2
  rescue SystemCallError => e
    warn "#{file}: cannot read YAML: #{e.message}"
    exit 2
  end
end

def safe_load_stream(file)
  class_loader = Psych::ClassLoader::Restricted.new(%w[Date Time], [])
  scanner = Psych::ScalarScanner.new(class_loader)
  visitor = Psych::Visitors::NoAliasRuby.new(scanner, class_loader)
  contents = file == "-" ? STDIN.read : File.read(file)

  Psych.parse_stream(contents, filename: file).children.map do |document|
    tag_kubernetes_string_scalars(document)
    visitor.accept(document)
  end
end

def tag_kubernetes_string_scalars(node)
  if node.is_a?(Psych::Nodes::Scalar) && node.plain && node.tag.nil? && node.value.start_with?(":")
    # Kubernetes has no Symbol scalar type; kubectl output may contain plain
    # string values like `value: :8000`, which Psych otherwise materializes as
    # Ruby Symbol objects.
    node.tag = YAML_STRING_TAG
  end

  Array(node.children).each { |child| tag_kubernetes_string_scalars(child) } if node.respond_to?(:children)
end

def expand_kubernetes_list(document)
  return [] unless document.is_a?(Hash)

  kind = document["kind"].to_s
  items = document["items"]
  return [[document, nil]] unless kind.end_with?("List") && items.is_a?(Array)

  items.each_with_index.each_with_object([]) do |(item, index), expanded|
    expanded << [item, index] if item.is_a?(Hash)
  end
end

def dig_hash(value, *keys)
  keys.reduce(value) do |current, key|
    return nil unless current.is_a?(Hash)

    current[key]
  end
end

def parse_policy_entries(value)
  value.to_s
       .lines
       .flat_map { |line| line.split(",") }
       .map(&:strip)
       .reject { |entry| entry.empty? || entry.start_with?("#") }
end

def resource_namespace(document)
  dig_hash(document, "metadata", "namespace") || "default"
end

def resource_id(document)
  "#{resource_namespace(document)}/#{dig_hash(document, "metadata", "name") || "<unnamed>"}"
end

def add_config_map_policy(config_maps, namespace, name, key, exact, prefixes, kind:)
  return if name.to_s.empty? || key.to_s.empty?

  data = config_maps[[namespace, name]]
  unless data
    warn "warning: referenced selector-policy ConfigMap #{namespace}/#{name} was not found"
    return
  end

  entries = parse_policy_entries(data[key])
  if kind == :prefix
    prefixes.concat(entries)
  else
    exact.merge(entries)
  end
end

def selector_label(key, show_keys)
  return key if show_keys

  prefix = key.include?(":") ? key.split(":", 2).first : "key"
  "#{prefix}:<redacted:#{Digest::SHA256.hexdigest(key)[0, 12]}>"
end

def external_secret?(document)
  document["kind"] == "ExternalSecret" &&
    document["apiVersion"].to_s.start_with?("external-secrets.io/")
end

def secret_store?(document)
  document["kind"] == "SecretStore" &&
    document["apiVersion"].to_s.start_with?("external-secrets.io/")
end

def cluster_secret_store?(document)
  document["kind"] == "ClusterSecretStore" &&
    document["apiVersion"].to_s.start_with?("external-secrets.io/")
end

def webhook_store?(document)
  dig_hash(document, "spec", "provider", "webhook").is_a?(Hash)
end

def external_secret_store_ref(document)
  ref = dig_hash(document, "spec", "secretStoreRef") || {}
  name = ref["name"].to_s
  return nil if name.empty?

  kind = ref["kind"].to_s.empty? ? "SecretStore" : ref["kind"].to_s
  if kind == "ClusterSecretStore"
    [:cluster_store, name]
  else
    [:store, "#{resource_namespace(document)}/#{name}"]
  end
end

def store_ref_selected?(ref, options, known_stores)
  return true unless ref

  kind, id = ref
  filters_configured = !options[:stores].empty? || !options[:cluster_stores].empty?
  if filters_configured
    return kind == :store ? options[:stores].include?(id) : options[:cluster_stores].include?(id)
  end

  return true unless known_stores[:any]
  if kind == :store
    return true unless known_stores[:stores].include?(id)

    return known_stores[:webhook_stores].include?(id)
  end
  if kind == :cluster_store
    return true unless known_stores[:cluster_stores].include?(id)

    return known_stores[:webhook_cluster_stores].include?(id)
  end

  true
end

def deployment?(document)
  document["kind"] == "Deployment" && document["apiVersion"].to_s.start_with?("apps/")
end

def remote_keys_from_external_secret(document)
  spec = document["spec"] || {}
  keys = []
  Array(spec["data"]).each do |entry|
    key = dig_hash(entry, "remoteRef", "key")
    keys << key if key && !key.to_s.empty?
  end
  Array(spec["dataFrom"]).each do |entry|
    key = dig_hash(entry, "extract", "key")
    keys << key if key && !key.to_s.empty?
  end
  keys
end

def env_entries(document)
  pod_containers(document).flat_map { |container| Array(container["env"]) }
end

def pod_containers(document)
  pod_spec = dig_hash(document, "spec", "template", "spec") || {}
  Array(pod_spec["containers"])
end

def selector_policy_env_names(document)
  env_entries(document)
    .map { |env| env["name"].to_s }
    .select { |name| SELECTOR_POLICY_ENV_NAMES.include?(name) }
end

def config_map_volumes(document)
  pod_spec = dig_hash(document, "spec", "template", "spec") || {}
  Array(pod_spec["volumes"]).each_with_object({}) do |volume, result|
    name = dig_hash(volume, "configMap", "name")
    next unless volume["name"] && name

    items = Array(dig_hash(volume, "configMap", "items")).each_with_object({}) do |item, paths|
      paths[item["path"]] = item["key"] if item["path"] && item["key"]
    end
    result[volume["name"]] = {
      name: name,
      items: items
    }
  end
end

def config_map_file_ref(volumes, container, path)
  return nil if volumes.empty?

  Array(container["volumeMounts"]).each do |mount|
    volume = volumes[mount["name"]]
    mount_path = mount["mountPath"]
    next unless volume && mount_path

    if mount["subPath"] && path == mount_path
      return [volume[:name], mount["subPath"]]
    end
    next unless path == mount_path || path.start_with?("#{mount_path}/")

    relative_path = path.delete_prefix("#{mount_path}/")
    key = volume[:items].fetch(relative_path, relative_path)
    return [volume[:name], key]
  end

  nil
end

files = manifest_files(paths)
if files.empty?
  warn "no YAML manifests found"
  exit 2
end

documents = []
config_maps = {}
known_stores = {
  any: false,
  stores: Set.new,
  cluster_stores: Set.new,
  webhook_stores: Set.new,
  webhook_cluster_stores: Set.new
}
each_document(files) do |file, document|
  documents << [file, document]
  name = dig_hash(document, "metadata", "name")
  if document["kind"] == "ConfigMap"
    config_maps[[resource_namespace(document), name]] = document["data"] || {} if name
  elsif secret_store?(document) && name
    id = "#{resource_namespace(document)}/#{name}"
    known_stores[:any] = true
    known_stores[:stores].add(id)
    known_stores[:webhook_stores].add(id) if webhook_store?(document)
  elsif cluster_secret_store?(document) && name
    known_stores[:any] = true
    known_stores[:cluster_stores].add(name)
    known_stores[:webhook_cluster_stores].add(name) if webhook_store?(document)
  end
end

provider_deployments = documents.select do |_, document|
  deployment?(document) && selector_policy_env_names(document).any?
end
provider_ids = provider_deployments.map { |_, document| resource_id(document) }.to_set

unless options[:providers].empty?
  missing_providers = options[:providers] - provider_ids
  unless missing_providers.empty?
    warn "provider Deployment(s) not found or have no selector-policy env: #{missing_providers.to_a.sort.join(", ")}"
    exit 2
  end
  provider_ids &= options[:providers]
end

if options[:providers].empty? && provider_ids.length > 1
  warn "multiple provider Deployments with selector policy were found: #{provider_ids.to_a.sort.join(", ")}"
  warn "run once per trust boundary with --provider NAMESPACE/NAME, or split the rendered manifest set"
  exit 2
end

manual_policy_configured = !options[:allowed_keys].empty? || !options[:allowed_prefixes].empty?
if provider_ids.empty? && !manual_policy_configured && !options[:allow_empty]
  warn "no provider Deployment with selector-policy environment was found"
  warn "include the rendered provider Deployment, pass --provider NAMESPACE/NAME, or use --allowed-key/--allowed-prefix for an explicit offline policy"
  exit 2
end

allowed_keys = options[:allowed_keys]
allowed_prefixes = options[:allowed_prefixes]
allow_all_selectors = false
external_secret_refs = []
warnings = []

documents.each do |file, document|
  if external_secret?(document)
    next unless store_ref_selected?(external_secret_store_ref(document), options, known_stores)

    namespace = resource_namespace(document)
    name = dig_hash(document, "metadata", "name") || "<unnamed>"
    target = dig_hash(document, "spec", "target", "name") || name
    remote_keys_from_external_secret(document).each do |key|
      external_secret_refs << {
        file: file,
        namespace: namespace,
        name: name,
        target: target,
        key: key.to_s
      }
    end
  end

  next unless deployment?(document)
  next unless provider_ids.include?(resource_id(document))

  deployment_namespace = resource_namespace(document)
  volumes = config_map_volumes(document)
  pod_containers(document).each do |container|
    container_env = Array(container["env"])
    next unless container_env.any? { |env| SELECTOR_POLICY_ENV_NAMES.include?(env["name"].to_s) }

    container_env.each do |env|
      name = env["name"].to_s
      case name
      when "BWESO_ALLOWED_KEYS"
        allowed_keys.merge(parse_policy_entries(env["value"]))
      when "BWESO_ALLOWED_KEY_PREFIXES"
        allowed_prefixes.concat(parse_policy_entries(env["value"]))
      when "BWESO_ALLOW_ALL_SELECTORS"
        allow_all_selectors ||= env["value"].to_s.casecmp?("true")
      when "BWESO_ALLOWED_KEYS_FILE", "BWESO_ALLOWED_KEY_PREFIXES_FILE"
        path = env["value"].to_s
        config_map_ref = config_map_file_ref(volumes, container, path)
        unless config_map_ref
          warnings << "#{file}: #{name} points at #{path.inspect}, " \
                      "but no ConfigMap volume mount covers it in the same container"
          next
        end
        config_map_name, key = config_map_ref
        add_config_map_policy(
          config_maps,
          deployment_namespace,
          config_map_name,
          key,
          allowed_keys,
          allowed_prefixes,
          kind: name == "BWESO_ALLOWED_KEY_PREFIXES_FILE" ? :prefix : :exact
        )
      end

      value_from = env["valueFrom"] || {}
      config_ref = value_from["configMapKeyRef"]
      next unless config_ref

      case name
      when "BWESO_ALLOWED_KEYS"
        add_config_map_policy(
          config_maps,
          deployment_namespace,
          config_ref["name"],
          config_ref["key"],
          allowed_keys,
          allowed_prefixes,
          kind: :exact
        )
      when "BWESO_ALLOWED_KEY_PREFIXES"
        add_config_map_policy(
          config_maps,
          deployment_namespace,
          config_ref["name"],
          config_ref["key"],
          allowed_keys,
          allowed_prefixes,
          kind: :prefix
        )
      end
    end
  end
end

uncovered = if allow_all_selectors
              []
            else
              external_secret_refs.reject do |ref|
                allowed_keys.include?(ref[:key]) ||
                  allowed_prefixes.any? { |prefix| ref[:key].start_with?(prefix) }
              end
            end

warnings.each { |warning| warn "warning: #{warning}" }
warn "warning: BWESO_ALLOW_ALL_SELECTORS=true covers every selector." if allow_all_selectors

puts "ExternalSecret remote keys: #{external_secret_refs.map { |ref| ref[:key] }.uniq.length}"
puts "selectorPolicy exact keys: #{allowed_keys.length}"
puts "selectorPolicy prefixes: #{allowed_prefixes.uniq.length}"
puts "selectorPolicy allow all: #{allow_all_selectors ? "true" : "false"}"

if external_secret_refs.empty? && !options[:allow_empty]
  warn "ERROR: no selected ExternalSecret remote keys were found."
  warn "Include ExternalSecret manifests, fix --store/--cluster-store filters, or pass --allow-empty for policy-only checks."
  exit 2
end

if uncovered.empty?
  puts "OK: every ExternalSecret remote key is covered by selector policy."
  exit 0
end

warn
warn "ERROR: ExternalSecret remote keys not covered by selector policy:"
uncovered.each do |ref|
  warn "  - #{ref[:namespace]}/#{ref[:name]} target=#{ref[:target]} " \
       "key=#{selector_label(ref[:key], options[:show_keys])} file=#{ref[:file]}"
end
warn
warn "Run with --show-keys only in a trusted local terminal if exact selectors are needed."
exit 1
