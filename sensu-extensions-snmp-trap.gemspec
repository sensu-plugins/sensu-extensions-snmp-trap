# coding: utf-8

Gem::Specification.new do |spec|
  spec.name          = "sensu-extensions-snmp-trap"
  spec.version       = "0.0.7"
  spec.authors       = ["Sensu-Extensions and contributors"]
  spec.email         = ["<sensu-users@googlegroups.com>"]

  spec.summary       = "Check extension to receive SNMP traps and translate them into check results"
  spec.description   = "Check extension to receive SNMP traps and translate them into check results"
  spec.homepage      = "https://github.com/sensu-extensions/sensu-extensions-snmp-trap"

  spec.files         = Dir.glob('{bin,lib}/**/*') + %w(LICENSE README.md CHANGELOG.md)
  spec.require_paths = ["lib"]

  spec.add_dependency "sensu-extension"
  spec.add_dependency "snmp", "1.2.0"

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "sensu-logger"
  spec.add_development_dependency "sensu-settings"
end
