# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{paypal_nvp}
  s.version = "0.3.0.freeagent.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2") if s.respond_to? :required_rubygems_version=
  s.authors = ["Olivier BONNAURE - solisoft"]
  s.date = %q{2016-04-19}
  s.description = %q{Paypal NVP API Class.}
  s.email = %q{o.bonnaure@solisoft.net}
  s.extra_rdoc_files = ["lib/paypal_nvp.rb", "README.rdoc"]
  s.files = ["init.rb", "lib/paypal_nvp.rb", "Rakefile", "README.rdoc", "paypal_nvp.gemspec"]
  s.homepage = %q{http://github.com/solisoft/paypal_nvp}
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "Paypal_nvp", "--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{paypal_nvp}
  s.rubygems_version = %q{1.7.2}
  s.summary = %q{Paypal NVP API Class.}

  s.metadata["allowed_push_host"] = "https://rubygems.pkg.github.com/fac"

  s.add_development_dependency "bundler", "~> 2.0"
  s.add_development_dependency "rake", "~> 12.0"
  s.add_development_dependency "rspec", "~> 3.0"

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
