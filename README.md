# OmniAuth::Speakap

Simple omniauth strategy for speakap, uses the speakap gem in order to fetch extra information from the API, so you need ot install them both.

## Installing the gems

```
gem 'speakap'
gem 'omniauth-speakap'
```

## Using with devise

Unfortunately, but due security speakap uses a per network secret and app id :( Meaning that we need to set those things in the setup phase

Let's say in `devise.rb`

```
  SPEAKAPP_SETUP_FOR_TENANTS = lambda do |env|
    req     = Rack::Request.new(env)
    # Fetch the network id from request, and get the private and pub key
    network = Network.find_by(speakap_network_eid: req.params['networkEID'])
    env['omniauth.strategy'].options[:speakap_network_eid] = network.speakap_network_eid
    env['omniauth.strategy'].options[:speakap_app_id] = network.speakap_app_id
    env['omniauth.strategy'].options[:speakap_secret_key] = network.speakap_secret_key
  end

  config.omniauth :leaplines, ENV["LEAP_KEY"], ENV["LEAP_SECRET"]
  config.omniauth :speakap, setup: SPEAKAPP_SETUP_FOR_TENANTS
```
