package goconnect

import "net/url"

const (
	connectScheme     = "https"
	connectAuthPath   = "/oauth/authorize"
	connectJWKPath    = "/oauth/public_keys.jwks"
	connectTokenPath  = "/oauth/token"
	connectLogoutPath = "/oauth/logout"
)

const (
	// StagingHost is the host name for the staging (aka testing) environment
	StagingHost = "connect.staging.telenordigital.com"
	// DefaultHost is the Connect ID production host. We recommend using this.
	DefaultHost = "connect.telenordigital.com"
)

const (
	// DefaultLoginRedirect is the default location the browser is redirected to
	// after the login has completed.
	DefaultLoginRedirect = "/"
	// DefaultLogoutRedirect is the default location the browser is redirected
	// to after the logout has completed
	DefaultLogoutRedirect = "/"

	// DefaultScopes are the scopes that will be requested when logging in
	DefaultScopes = "openid profile email phone"

	// DefaultLoginRedirectURI is the default redirect url for login.
	DefaultLoginRedirectURI = "http://localhost:8080/connect/oauth2callback"

	// DefaultLogoutRedirectURI is the default redirect url for logout.
	DefaultLogoutRedirectURI = "http://localhost:8080/connect/logoutcallback"

	// DefaultLoginCallback is the name of the endpoint that the CONNECT ID
	// OAuth server redirects to when a login roundtrip is completed
	DefaultLoginCallback = "oauth2callback"

	// DefaultLogoutCallback is the name of the endpoint that the CONNECT ID
	// OAuth server redirects to when a logout roundtrip is completed
	DefaultLogoutCallback = "logoutcallback"

	// DefaultLoginInit is the name of the endpoint the client accesses to
	// start a login roundtrip to the OAuth server
	DefaultLoginInit = "login"

	// DefaultLogoutInit is the name of the endpoint the client accesses to
	// start a logout roundtrip to the OAuth server
	DefaultLogoutInit = "logout"

	// DefaultProfileEndpoint is the name of the endpoint the client uses to access
	// session profile information.
	DefaultProfileEndpoint = "profile"
)

// ClientConfig holds the ConnectID configuration. This is only used internally
type ClientConfig struct {
	Host                   string // Host is the hostname of the Connect ID host to use.
	Scopes                 string // Scopes is the OAuth scopes to use when logging in.
	LogoutRedirectURI      string // LogoutRedirectURI is the redirect URI for completed logins.
	LoginRedirectURI       string // LoginRedirectURI is the redirect URI for completed logouts.
	ClientID               string // ClientID is the OAuth client ID.
	Password               string // Password is the (optional) secret.
	LoginCompleteRedirect  string // LoginCompleteRedirect is where the client is redirected after a successful login roundtrip.
	LogoutCompleteRedirect string // LogoutCompleteRedirect is where the client is redirected after a logout.
	LoginCallback          string // Name for endpoint that receives login callback
	LogoutCallback         string // Name for endpoint that receives logout callback
	LoginInit              string // Name for endpoint that starts a login roundtrip
	LogoutInit             string // Name for endpoint that starts a logout roundtrip
	ProfileEndpoint        string // Name for session profile information endpoint
	UseSecureCookie        bool   // Secure flag for cookie
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
	if ret.LogoutRedirectURI == "" {
		ret.LogoutRedirectURI = DefaultLogoutRedirectURI
	}
	if ret.LoginRedirectURI == "" {
		ret.LoginRedirectURI = DefaultLoginRedirectURI
	}
	if ret.LoginCompleteRedirect == "" {
		ret.LoginCompleteRedirect = DefaultLoginRedirect
	}
	if ret.LogoutCompleteRedirect == "" {
		ret.LogoutCompleteRedirect = DefaultLogoutRedirect
	}
	if ret.LoginCallback == "" {
		ret.LoginCallback = DefaultLoginCallback
	}
	if ret.LogoutCallback == "" {
		ret.LogoutCallback = DefaultLogoutCallback
	}
	if ret.LoginInit == "" {
		ret.LoginInit = DefaultLoginInit
	}
	if ret.LogoutInit == "" {
		ret.LogoutInit = DefaultLogoutInit
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
