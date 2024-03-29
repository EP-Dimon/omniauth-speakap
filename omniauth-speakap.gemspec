# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/speakap/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-speakap"
  spec.version       = Omniauth::Speakap::VERSION
  spec.authors       = ["Emile Bosch"]
  spec.email         = ["emilebosch@me.com"]
  spec.description   = %q{An OmniAuth strategy to accept Speakap SSO}
  spec.summary       = %q{An OmniAuth strategy to accept Speakap SSO}
  spec.homepage      = "http://github.com/runteam/omniauth-speakap"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "speakap", "~> 0.1"
  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "guard"
  spec.add_development_dependency "guard-rspec"
  spec.add_development_dependency "rack-test"
  
  spec.add_dependency "omniauth", "~> 2.1"
end
