require 'rubygems'
require 'rake'
require 'rake/testtask'
require 'rake/packagetask'
require 'rake/gempackagetask'
require 'rake/clean'

CLEAN.include('pkg/*')
PKG_VERSION = "1.0.2"

spec = Gem::Specification.new do |s|
  s.platform = Gem::Platform::RUBY
  s.summary = "Google Apps support for ruby-openid"
  s.name = 'ruby-openid-apps-discovery'
  s.version = PKG_VERSION
  s.add_dependency('ruby-openid', '>=2.1.7')
  s.require_path = 'lib'
  s.files = FileList['lib/**/*.rb', 'lib/**/*.crt'].to_a
  s.description = <<EOF
Extension to ruby-openid that enables discovery for Google Apps domains
EOF
end

Rake::TestTask.new do |t|
   t.test_files = FileList['test/test*.rb']
   t.verbose = true
end
 
Rake::PackageTask.new("ruby-openid-apps-discovery", "1.0") do |p|
  p.need_tar = true
  p.package_files.include("lib/**/*.rb")
  p.package_files.include("lib/**/*.crt")
end

Rake::GemPackageTask.new(spec) do |pkg|
  pkg.need_zip = true
  pkg.need_tar = true
end