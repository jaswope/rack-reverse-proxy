require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe Rack::ReverseProxy do
  include Rack::Test::Methods
  include WebMock::API

  def app
    Rack::ReverseProxy.new
  end

  def dummy_app
    lambda { |env| [200, {}, ['Dummy App']] }
  end

  describe "as middleware" do
    def app
      Rack::ReverseProxy.new(dummy_app) do
        reverse_proxy '/test', 'http://example.com/', {:preserve_host => true}
        reverse_proxy '/2test', lambda{ |env| 'http://example.com/'}
      end
    end

    it "should forward requests to the calling app when the path is not matched" do
      get '/'
      last_response.body.should == "Dummy App"
      last_response.should be_ok
    end

    it "should proxy requests when a pattern is matched" do
      stub_request(:get, 'http://example.com/test').to_return({:body => "Proxied App"})
      get '/test'
      last_response.body.should == "Proxied App"
    end

    it "should proxy requests to a lambda url when a pattern is matched" do
      stub_request(:get, 'http://example.com/2test').to_return({:body => "Proxied App2"})
      get '/2test'
      last_response.body.should == "Proxied App2"
    end

    it "the response header should never contain Status" do
      stub_request(:any, 'example.com/test/stuff').to_return(:headers => {'Status' => '200 OK'})
      get '/test/stuff'
      last_response.headers['Status'].should == nil
    end

    it "the response header should never transfer-encoding" do
      stub_request(:any, 'example.com/test/stuff').to_return(:headers => {'transfer-encoding' => 'Chunked'})
      get '/test/stuff'
      last_response.headers['transfer-encoding'].should == nil
    end

    it "should set the Host header" do
      stub_request(:any, 'example.com/test/stuff')
      get '/test/stuff'
      a_request(:get, 'http://example.com/test/stuff').with(:headers => {"Host" => "example.com"}).should have_been_made
    end

    describe "with preserve host turned off" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy '/test', 'http://example.com/', {:preserve_host => false}
        end
      end

      it "should not set the Host header" do
        stub_request(:any, 'example.com/test/stuff')
        get '/test/stuff'
        a_request(:get, 'http://example.com/test/stuff').with(:headers => {"Host" => "example.com"}).should_not have_been_made
        a_request(:get, 'http://example.com/test/stuff').should have_been_made
      end
    end

    describe "with basic auth turned on" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy '/test', 'http://example.com/', {:username => "joe", :password => "shmoe"}
        end
      end

      it "should make request with basic auth" do
        stub_request(:get, "http://joe:shmoe@example.com/test/stuff").to_return(:body => "secured content")
        get '/test/stuff'
        last_response.body.should == "secured content"
      end
    end
    
    describe "with headers dictionary provided" do
      context 'when the header does not exist in the source request' do
        def app
          Rack::ReverseProxy.new(dummy_app) do
            reverse_proxy '/test', 'http://example.com/', {:headers => {'X-EXAMPLE-HEADER' => 'A value'}}
          end
        end
        
        it "should add the provided headers" do
          stub_request(:any, 'example.com/test/stuff')
          get '/test/stuff'
          a_request(:get, 'http://example.com/test/stuff').with(:headers => {"X-EXAMPLE-HEADER" => "A value"}).should have_been_made
        end
      end
      
      context 'when the header already appears in the source request' do
        def app
          Rack::ReverseProxy.new(dummy_app) do
            reverse_proxy '/test', 'http://example.com/', {:headers => {'X-EXAMPLE-HEADER' => 'New value'}}
          end
        end
        
        it "should replace the existing Headers value" do
          headers = {'Accept'=>'*/*', 'Cookie'=>'', 'Host'=>'example.com', 'User-Agent'=>'Ruby', 
                     'X-Example-Header'=>'New value', 'X-Forwarded-Host'=>'example.org'}
          stub_request(:any, 'example.com/test/stuff').with(:headers => headers)
          get '/test/stuff', {}, {"X-EXAMPLE-HEADER" => "Original value"}
          a_request(:get, 'http://example.com/test/stuff').with(:headers => {"X-EXAMPLE-HEADER" => "New value"}).should have_been_made
        end
      end
    end
    
    describe 'with headers proc provided' do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy('/test', 'http://example.com/', :headers => lambda do |headers|
            headers['X-FORWARDED-FOR'].gsub!(', 127.0.0.1', '') if headers['X-FORWARDED-FOR']
            headers
          end)
        end
      end
      
      it "should yield the headers to the proc for manipulation" do
        headers = {'Accept'=>'*/*', 'Cookie'=>'', 'Host'=>'example.com', 'User-Agent'=>'Ruby', 
                   'X-Forwarded_For'=>'174.254.197.191', 'X-Forwarded-Host'=>'example.org'}
        stub_request(:any, 'example.com/test/stuff').with(:headers => headers)
        get '/test/stuff', {}, {'HTTP_X_Forwarded_For'=>'174.254.197.191, 127.0.0.1'}
        a_request(:get, 'http://example.com/test/stuff').with(:headers => {"X-Forwarded-For" => "174.254.197.191"}).should have_been_made
      end
    end

    describe "with ambiguous routes and all matching" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy_options :matching => :all
          reverse_proxy '/test', 'http://example.com/'
          reverse_proxy /^\/test/, 'http://example.com/'
        end
      end

      it "should throw an exception" do
        lambda { get '/test' }.should raise_error(Rack::AmbiguousProxyMatch)
      end
    end

    describe "with ambiguous routes and first matching" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy_options :matching => :first
          reverse_proxy '/test', 'http://example1.com/'
          reverse_proxy /^\/test/, 'http://example2.com/'
        end
      end

      it "should throw an exception" do
        stub_request(:get, 'http://example1.com/test').to_return({:body => "Proxied App"})
        get '/test'
        last_response.body.should == "Proxied App"
      end
    end

    describe "with a route as a regular expression" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy %r|^/test(/.*)$|, 'http://example.com$1'
        end
      end

      it "should support subcaptures" do
        stub_request(:get, 'http://example.com/path').to_return({:body => "Proxied App"})
        get '/test/path'
        last_response.body.should == "Proxied App"
      end
    end

    describe "with a https route" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy '/test', 'https://example.com'
        end
      end

      it "should make a secure request" do
        stub_request(:get, 'https://example.com/test/stuff').to_return({:body => "Proxied Secure App"})
        get '/test/stuff'
        last_response.body.should == "Proxied Secure App"
      end

    end

    describe "with a route as a string" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy '/test', 'http://example.com'
          reverse_proxy '/path', 'http://example.com/foo$0'
        end
      end

      it "should append the full path to the uri" do
        stub_request(:get, 'http://example.com/test/stuff').to_return({:body => "Proxied App"})
        get '/test/stuff'
        last_response.body.should == "Proxied App"
      end

    end

    describe "with a generic url" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy '/test', 'example.com'
        end
      end

      it "should throw an exception" do
        lambda{ app }.should raise_error(Rack::GenericProxyURI)
      end
    end

    describe "with a matching route" do
      def app
        Rack::ReverseProxy.new(dummy_app) do
          reverse_proxy '/test', 'http://example.com/'
        end
      end

      %w|get head delete put post|.each do |method|
        describe "and using method #{method}" do
          it "should forward the correct request" do
            stub_request(method.to_sym, 'http://example.com/test').to_return({:body => "Proxied App for #{method}"})
            eval "#{method} '/test'"
            last_response.body.should == "Proxied App for #{method}"
          end

          if %w|put post|.include?(method)
            it "should forward the request payload" do
              stub_request(method.to_sym, 'http://example.com/test').to_return { |req| {:body => req.body} }
              eval "#{method} '/test', {:test => 'test'}"
              last_response.body.should == "test=test"
            end
          end
        end
      end
    end
  end

  describe "as a rack app" do
    it "should respond with 404 when the path is not matched" do
      get '/'
      last_response.should be_not_found
    end
  end

end
