# PayPal NVP

This gem allows you to connect your Ruby on Rails application to the PayPal NVP API.

## Installation

You can install the gem in one of two ways. The first is using the gem install command from the command line:

    $ gem install paypal_nvp

And the second is using Bundler. Add `gem 'paypal_nvp'` to your Gemfile, then install with the following command:

    $ bundle install

PayPalNVP can be configured either via its initializer or an optional `paypal.yml` file in your `config` directory.

```yml
# You can authenticate using either API Certificate (`key_path`/`cert_path`) or API Signature (`signature`).
# All fields are mandatory.

# Certificate-based authentication
sandbox:
  url:  "https://api.sandbox.paypal.com/nvp"
  user: "o.bonn_1237393081_biz_api1.solisoft.net"
  pass: "1237393093"
  key_path: /etc/paypal/key.pem
  cert_path: /etc/paypal/crt.pem
  open_timeout: 3
  read_timeout: 60

# Signature-based authentication
sandbox:
  url:  "https://api-3t.sandbox.paypal.com/nvp"
  user: "o.bonn_1237393081_biz_api1.solisoft.net"
  pass: "1237393093"
  signature: "AU2Yv5COwWPCfeYLv34Z766F-gfNAzX6LaQE6VZkHMRq35Gmite-bMXu"
  open_timeout: 3
  read_timeout: 60

live:
  url:  "https://api-3t.paypal.com/nvp"
  user: "o.bonn_1237393081_biz_api1.solisoft.net"
  pass: "1237393093"
  signature: "AU2Yv5COwWPCfeYLv34Z766F-gfNAzX6LaQE6VZkHMRq35Gmite-bMXu"
  open_timeout: 3
  read_timeout: 60
```

## Example usage

```rb
p = PaypalNVP.new(true) # true means "use sandbox"

# Or you can specify paramaters directly
p = PaypalNVP.new(true, {
  :user => "o.bonn_1237393081_biz_api1.solisoft.net",
  :pass => "1237393093",
  :signature => "AU2Yv5COwWPCfeYLv34Z766F-gfNAzX6LaQE6VZkHMRq35Gmite-bMXu",
  :url => "https://api-3t.sandbox.paypal.com/nvp",
  :open_timeout => 3,
  :read_timeout => 60,
})

data = {
  version: "50.0", # default
  method: "MyPaypalMethod",
  amt: "55"
}
result = p.call_paypal(data) # will return a hash
puts result["ACK"] # Success
```

## PayPal API Documentation

https://developer.paypal.com/api/nvp-soap/nvp/
