# GoConnect - a library for Telenor Connect ID

This library makes it easy to integrate your Go (web) service with the Telenor 
Connect ID authorization and authentication service.

# Where's the demo?
Clone (or fork) the https://github.com/telenordigital/goconnect-sample/ 
repository to get a working demo with a development client included.

# Where's the documentation?

[![GoDoc](https://godoc.org/github.com/telenordigital/goconnect?status.svg)](https://godoc.org/github.com/telenordigital/goconnect)

## Getting your own CONENCT ID client config
You can get your own CONNECT client configuration by going to the 
https://docs.telenordigital.com/ site and filling out the form there. Processing
 takes a business day or two. In the meanwhile you can use the client 
 configuration included in this sample.

## About the redirect URI parameters
The redirect URI parameters that you use when logging in must be configured 
both on the client side (ie your service) and on the server side (ie on the
Telenor CONNECT ID servers). The service will only accept the configured 
redirect URI parameters to be used so you can't use custom redirects for 
each deployment you have.

## Using the same Connect ID client config for different deployments
You probably want to several different client types - one for your testing 
environment, one for development and one for your production environment. 

You can configure multiple redirect URLs for each client so in theory you could
use the same client configuration for all of your environments but it makes
sense to have one set for development and testing (that accepts redirects to
f.e. http://localhost:8080/connect/oauth2callback when you run the service locally and
https://test.myservice.example.com/connect/oauth2callback for your testing environment)
and another set for your production service (that only allows the redirect URI 
to be set to https://myservice.example.com/connect/complete). 

If you want to add additional redirect URIs for your clients please do not 
hesitate to mail us. 

# Endpoints exposed by the library

* `<path>/login` -- start login roundtrip
* `<path>/oauth2callback` -- OAuth callback
* `<path>/logout` -- start logout roundtrip 
* `<path>/logoutcallback` -- start logout roundtrip 
* `<path>/profile` -- Info callback

## Demo client setup
    Client ID:   telenordigital-connectexample-web
    RedirectURI: http://localhost;8080/oauth2callback (login complete)
                 http://localhost:8080/logoutcallback (logout complete)

    Auth init: https://connect.telenordigital.com/oauth/authorize
    Logout init: https://connect.telenordigital.com/oauth/logout
    Token endpoint: https://connect.telenordigital.com/oauth/token
    JWK endpoint: https://connect.telenordigital.com/oauth/public_keys.jwks
