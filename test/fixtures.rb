require 'rubygems'
require 'gapps_openid'
require 'test/unit'

class Fixtures

  def self.read_file(name)
    file = File.join(File.dirname(__FILE__), 'fixtures', name)
    File.read(file)
  end
  
end
