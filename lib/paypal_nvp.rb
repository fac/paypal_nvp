require "net/https"
require "openssl"
require "cgi"
require "logger"

class PaypalNVP
  def self.included(base)
    base.extend ClassMethods
  end

  DEFAULT_OPEN_TIMEOUT = nil
  DEFAULT_READ_TIMEOUT = 60

  def initialize(sandbox = false, extras = {})
    type = sandbox ? "sandbox" : "live"
    config = YAML.load_file("#{Rails.root}/config/paypal.yml") rescue nil
    @logger = defined?(Rails.logger) && Rails.logger || Logger.new(STDOUT)

    # By default we use the 50.0 API version.
    # At 30 Apr 2012, version 87.0 and provides additional shipping information.
    extras[:version] ||= "50.0"

    if config
      @url  = config[type]["url"]
      @user = config[type]["user"]
      @pass = config[type]["pass"]
      @signature = config[type]["signature"]
      @key_path = config[type]["key_path"]
      @cert_path = config[type]["cert_path"]
      @rootCA = config[type]["rootca"]
      @open_timeout = config[type]["open_timeout"]
      @read_timeout = config[type]["read_timeout"]
    else
      @url  = extras.delete(:url)
      @user = extras.delete(:user)
      @pass = extras.delete(:pass)
      @signature = extras.delete(:signature)
      @rootCA = extras.delete(:rootca)

      @key_path = extras.delete(:key_path)
      @cert_path = extras.delete(:cert_path)

      @open_timeout = extras.delete(:open_timeout)
      @read_timeout = extras.delete(:read_timeout)
    end

    # If network timeout is not set above, we simply default both of them to default values
    @open_timeout ||= DEFAULT_OPEN_TIMEOUT
    @read_timeout ||= DEFAULT_READ_TIMEOUT

    @extras = extras
    @rootCA = @rootCA || '/etc/ssl/certs'
  end

  def call_paypal(data)
    # items in the data hash should take precedence over preconfigured values,
    # to allow for maximum flexibility:
    params = @extras.dup
    params.merge!({ "USER" => @user, "PWD" => @pass })

    # Signature authentication
    params.merge!({ "SIGNATURE" => @signature }) if @signature
    params.merge!(data)
    qs = []
    params.each do |key, value|
      qs << "#{key.to_s.upcase}=#{URI::DEFAULT_PARSER.escape(value.to_s, /\+/)}"
    end
    qs = "#{qs * "&"}"

    uri = URI.parse(@url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    if File.directory? @rootCA
      http.ca_path = @rootCA
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.verify_depth = 5
    elsif File.exist?(@rootCA)
      http.ca_file = @rootCA
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.verify_depth = 5
    else
      @logger.warn "[PaypalNVP] No ssl certs found. Paypal communication will be insecure. DO NOT DEPLOY"
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    # certificate authentication
    if cert_auth?
      http.cert = OpenSSL::X509::Certificate.new(cert)
      http.key = OpenSSL::PKey::RSA.new(priv_key)
    end

    http.open_timeout = @open_timeout
    http.read_timeout = @read_timeout

    response = http.start {
      http.request_post(uri.path, qs) {|res|
        res
      }
    }
    data = { :response => response }
    if response.kind_of? Net::HTTPSuccess
      response.body.split("&").each do |element|
        a = element.split("=")
        data[a[0]] = CGI.unescape(a[1]) if a.size == 2
      end
    end
    data
  end

  private

  def cert
    File.read(@cert_path)
  end

  def priv_key
    File.read(@key_path)
  end

  def cert_auth?
    !@signature
  end
end
