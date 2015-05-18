# -*- ruby -*-

require 'rubygems'
require 'hoe'

Hoe.plugin :minitest

spec = Hoe.spec 'puttykey' do
  developer "Lars Christensen", "larsch@belunktum.dk"
  license "MIT"
end

desc "Test packaged gem"
task :package_test => :package do |x|
  pkg = "pkg/#{spec.name}-#{spec.version}"
  gem_path = Dir["#{pkg}*.gem"].first
  rm_rf "package_test"
  mkdir "package_test"
  chdir "package_test" do
    sh "tar", "xf", "../" + gem_path
    sh "tar", "xfz", "data.tar.gz"
    sh "ruby", "-S", "rake", "test"
  end
  rm_rf "package_test"
end

# vim: syntax=ruby
