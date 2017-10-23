package goconnect

/*
**   Copyright 2017 Telenor Digital AS
**
**  Licensed under the Apache License, Version 2.0 (the "License");
**  you may not use this file except in compliance with the License.
**  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
 */
import "net/url"

const (
	connectScheme     = "https"
	connectAuthPath   = "/oauth/authorize"
	connectJWKPath    = "/oauth/public_keys.jwks"
	connectTokenPath  = "/oauth/token"
	connectLogoutPath = "/oauth/logout"
)

const (
	// DefaultHost is the Connect ID production host. We recommend using this.
	DefaultHost = "connect.telenordigital.com"

	// StagingHost is the host name for the staging (aka testing) environment
	StagingHost = "connect.staging.telenordigital.com"
)

// These constants provide default values for ClientConfig.
const (
	DefaultScopes                    = "openid profile email phone"
	DefaultLoginInit                 = "login"
	DefaultLogoutInit                = "logout"
	DefaultLoginRedirectURI          = "http://localhost:8080/connect/oauth2callback"
	DefaultLogoutRedirectURI         = "http://localhost:8080/connect/logoutcallback"
	DefaultLoginRedirect             = "oauth2callback"
	DefaultLogoutRedirect            = "logoutcallback"
	DefaultLoginCompleteRedirectURI  = "/"
	DefaultLogoutCompleteRedirectURI = "/"
	DefaultProfileEndpoint           = "profile"
)

// ClientConfig holds the ConnectID configuration.
type ClientConfig struct {
	Host                      string // Host is the name of the Connect ID host to use.
	Scopes                    string // Scopes is a space separated list of the OAuth scopes to use when logging in.
	ClientID                  string // ClientID is the OAuth client ID.
	Password                  string // Password is the (optional) secret.
	LoginInit                 string // LoginInit is the endpoint for starting a login.
	LogoutInit                string // LogoutInit is the endpoint for starting a logout.
	LoginRedirectURI          string // LoginRedirectURI is where the OAuth server redirects after a successful login.
	LogoutRedirectURI         string // LogoutRedirectURI is where the OAuth server redirects after a successful logout.
	LoginRedirect             string // LoginRedirect is the endpoint that serves - and is thus typically a suffix of - LoginRedirectURI.
	LogoutRedirect            string // LogoutRedirect is the endpoint that serves - and is thus typically a suffix of - LogoutRedirectURI.
	LoginCompleteRedirectURI  string // LoginCompleteRedirectURI is where goconnect redirects after a successful login.
	LogoutCompleteRedirectURI string // LogoutCompleteRedirectURI is where goconnect redirects after a successfull logout.
	ProfileEndpoint           string // ProfileEndpoint is the session profile information endpoint.
	UseSecureCookie           bool   // UseSecureCookie indicates whether to use a secure cookie.
}

// NewDefaultConfig creates a configuration with default values prepopulated. If the
// parameter is set in the overrides parameter it won't be set.
func NewDefaultConfig(overrides ClientConfig) ClientConfig {
	ret := overrides
	if ret.Host == "" {
		ret.Host = DefaultHost
	}
	if ret.Scopes == "" {
		ret.Scopes = DefaultScopes
	}
	if ret.LoginInit == "" {
		ret.LoginInit = DefaultLoginInit
	}
	if ret.LogoutInit == "" {
		ret.LogoutInit = DefaultLogoutInit
	}
	if ret.LoginRedirectURI == "" {
		ret.LoginRedirectURI = DefaultLoginRedirectURI
	}
	if ret.LogoutRedirectURI == "" {
		ret.LogoutRedirectURI = DefaultLogoutRedirectURI
	}
	if ret.LoginRedirect == "" {
		ret.LoginRedirect = DefaultLoginRedirect
	}
	if ret.LogoutRedirect == "" {
		ret.LogoutRedirect = DefaultLogoutRedirect
	}
	if ret.LoginCompleteRedirectURI == "" {
		ret.LoginCompleteRedirectURI = DefaultLoginCompleteRedirectURI
	}
	if ret.LogoutCompleteRedirectURI == "" {
		ret.LogoutCompleteRedirectURI = DefaultLogoutCompleteRedirectURI
	}
	if ret.ProfileEndpoint == "" {
		ret.ProfileEndpoint = DefaultProfileEndpoint
	}

	return ret
}

// Helper function to construct an URL for requests
func buildConnectURL(config ClientConfig, path string) url.URL {
	return url.URL{
		Scheme: connectScheme,
		Host:   config.Host,
		Path:   path,
	}
}
