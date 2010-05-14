require 'rubygems'
require 'gapps_openid'
require 'test/fixtures'
require 'test/unit'

class DiscoveryTest < Test::Unit::TestCase

  def setup
    @discovery = OpenID::GoogleDiscovery.new
  end
  
  def test_fetch_host_meta
    url = @discovery.fetch_host_meta("google.com")
    assert(!url.nil?, "Should have found link for google.com")
    parsed_url = URI::parse(url)
    assert(!parsed_url.scheme.nil?, "URL not valid")
  end
  
  def test_fetch_no_host_meta
    url = @discovery.fetch_host_meta("___NOT_A_VALID_DOMAIN__.com")
    assert(url.nil?)
  end
  
  def test_fetch_xrds
    url = @discovery.fetch_host_meta("google.com")
    xrds, secure = @discovery.fetch_secure_xrds("google.com",url)
    assert_not_nil(xrds, "Should have found XRDS for google.com")
  end
  
  def test_get_user_xrds_url
    xml = Fixtures.read_file("google-site-xrds.xml")
    url, next_authority = @discovery.get_user_xrds_url(xml, "http://google.com/openid?id=12345")
    assert_equal("hosted-id.google.com", next_authority)
    assert_equal("https://www.google.com/accounts/o8/user-xrds?uri=http%3A%2F%2Fgoogle.com%2Fopenid%3Fid%3D12345", url)
  end
  
  def test_site_discover
    info = @discovery.perform_discovery("google.com")
    assert_not_nil(info, "should have found discovery info for google.com")  
  end

  def test_site_discover_url
    info = @discovery.perform_discovery("http://marketplace-test.com/")
    assert_not_nil(info, "should have found discovery info for http://marketplace-test.com/")  
  end

  def test_site_discover_gmail
    info = @discovery.perform_discovery("gmail.com")
    assert_not_nil(info, "should have found discovery info for gmail.com")  
  end
  
  def test_user_discover
    info = @discovery.perform_discovery("http://google.com/openid?id=109052429299753016317")
    assert_not_nil(info, "should have found discovery for user id")
  end
  
end
