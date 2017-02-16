package goconnect

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// connectIDCookieName is the name of the cookie used for session management
	connectIDCookieName = "goconnect"
)

// GoConnect is the main entry point to Telenor CONNECT ID client API.
type GoConnect struct {
	Config   ClientConfig
	storage  Storage
	jwkCache *jwkCache
	mutex    *sync.Mutex
}

// NewConnectID creates a new ConnectID client.
func NewConnectID(config ClientConfig) *GoConnect {
	jwkURL := buildConnectURL(config, connectJWKPath)
	client := &GoConnect{
		Config:   config,
		storage:  NewMemoryStorage(),
		jwkCache: newJWKCache(jwkURL.String()),
		mutex:    &sync.Mutex{},
	}
	go client.tokenRefresher()
	return client
}

func (t *GoConnect) tokenRefresher() {
	const sleepTime = time.Second * 30
	for {
		<-time.After(sleepTime)
		t.storage.RefreshTokens(t.Config, sleepTime)
	}
}

// Start the login process
func (t *GoConnect) startLogin(w http.ResponseWriter, r *http.Request) {
	randombytes := make([]byte, 10)
	n, err := rand.Read(randombytes)
	if n != len(randombytes) {
		log.Printf("Couldn't read more than %d bytes, requested %d", n, len(randombytes))
	}
	if err != nil {
		log.Printf("Got error reading random bytes: %v", err)
	}

	loginToken := hex.EncodeToString(randombytes)
	if err := t.storage.PutLoginNonce(loginToken); err != nil {
		log.Printf("Error storing token: %v", err)
	}

	newURL := buildConnectURL(t.Config, connectAuthPath)
	q := newURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", t.Config.ClientID)
	q.Set("scope", DefaultScopes) // "openid profile email phone telenordigital.loracore")
	q.Set("acr_values", "2")
	q.Set("redirect_uri", t.Config.LoginRedirectURI)
	q.Set("state", loginToken)
	newURL.RawQuery = q.Encode()
	// Remove any old session cookie before starting the roundtrip.
	http.SetCookie(w, &http.Cookie{Name: connectIDCookieName, MaxAge: -1, HttpOnly: true, Path: "/"})

	http.Redirect(w, r, newURL.String(), http.StatusSeeOther)
}

// tokenResponse is the response from the connectTokenURL endpoint
type tokenResponse struct {
	AccessToken        string `json:"access_token"`
	TokenType          string `json:"token_type"`
	AccessTokenExpires int    `json:"expires_in"`
	RefreshToken       string `json:"refresh_token"`
	Scope              string `json:"scope"`
	JWT                string `json:"id_token"`
}

// Get tokens from code. The returned token response is the output from
// the OAuth service.
func (t *GoConnect) getTokens(code string) (tokenResponse, error) {
	nothing := tokenResponse{}
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", t.Config.LoginRedirectURI)
	data.Set("client_id", t.Config.ClientID)

	tokenURL := buildConnectURL(t.Config, connectTokenPath)
	req, err := http.NewRequest("POST", tokenURL.String(), bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nothing, fmt.Errorf("Could not create request: %v", err)
	}
	if t.Config.Password != "" {
		req.SetBasicAuth(t.Config.ClientID, t.Config.Password)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nothing, fmt.Errorf("Could not execute request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nothing, fmt.Errorf("Could not convert tokens. Expected 200 OK from OAuth server but got %d", resp.StatusCode)
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nothing, fmt.Errorf("Could not read body from response: %v", err)
	}
	tokens := tokenResponse{}
	if err := json.Unmarshal(buf, &tokens); err != nil {
		return nothing, fmt.Errorf("Could not unmarshal response: %v", err)
	}
	return tokens, nil
}

// Callback from OAuth server when login is completed
func (t *GoConnect) loginComplete(w http.ResponseWriter, r *http.Request) {
	// Login is complete - check that code matches the state parameter sent earlier. States
	// are kept for N hours? Mismatch => error page saying "try again"
	// obtain tokens, store token and set cookie
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Verify that state is sent previously
	if err := t.storage.CheckLoginNonce(state); err != nil {
		http.Error(w, "Unknown state token.", http.StatusBadRequest)
		return
	}

	errcode := r.URL.Query().Get("error")
	if errcode != "" {
		// There's an error message. Just redirect back to the logout page.
		log.Printf("Got error from OAuth server: %s - %s", errcode, r.URL.Query().Get("error_description"))
		http.Redirect(w, r, t.Config.LogoutCompleteRedirect, http.StatusSeeOther)
		return
	}

	// Pull the JWT from the OAuth server, then verify title
	tokens, err := t.getTokens(code)
	if err != nil {
		log.Printf("Could not get tokens: %v", err)
		http.Error(w, "Could not pull JWT token from server", http.StatusServiceUnavailable)
		return
	}

	jwks, err := t.jwkCache.GetJWK()
	if err != nil {
		log.Printf("Got error retrieving JWKs: %v", err)
		http.Error(w, "Error validating JWT", http.StatusServiceUnavailable)
		return
	}
	jwt, err := newJWT(tokens.JWT, jwks, t.Config)
	if err != nil {
		http.Error(w, "Got error converting token string into JWT", http.StatusInternalServerError)
		return
	}

	// Invariant: JWT is valid and we have tokens for the user.
	// Create a new session.
	session := newSession(jwt, tokens.AccessToken, tokens.RefreshToken, tokens.AccessTokenExpires)
	if err := t.storage.PutSession(session); err != nil {
		http.Error(w, "Got error storing session", http.StatusServiceUnavailable)
		return
	}
	cookie := &http.Cookie{
		Name:     connectIDCookieName,
		Value:    session.id,
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, t.Config.LoginCompleteRedirect, http.StatusSeeOther)
}

// Check if there is a session. Set error and return otherwise
func (t *GoConnect) isAuthorized(w http.ResponseWriter, r *http.Request) (bool, *Session) {
	cookie, err := r.Cookie(connectIDCookieName)
	if cookie == nil || err == http.ErrNoCookie {
		http.Error(w, "You are not authorized to view this page. Try logging in again.", http.StatusUnauthorized)
		return false, nil
	}
	session, err := t.storage.GetSession(cookie.Value)
	if err == errorNoSession {
		http.Error(w, "You are not authorized to view this page. Try logging in again.", http.StatusUnauthorized)
		return false, nil
	}

	return true, session
}

// Show session info (if there is one)
func (t *GoConnect) showSessionInfo(w http.ResponseWriter, r *http.Request) {
	auth, session := t.isAuthorized(w, r)
	if !auth {
		return
	}
	// Invariant: OK - session is found. Write information
	bytes, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		log.Printf("Got error converting session to JSON: %v", err)
		http.Error(w, "Session read error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

// Start logout roundtrip
func (t *GoConnect) startLogout(w http.ResponseWriter, r *http.Request) {
	randombytes := make([]byte, 10)
	n, err := rand.Read(randombytes)
	if n != len(randombytes) {
		log.Printf("Couldn't read more than %d bytes, requested %d", n, len(randombytes))
	}
	if err != nil {
		log.Printf("Got error reading random bytes: %v", err)
	}

	nonce := hex.EncodeToString(randombytes)
	if err := t.storage.PutLogoutNonce(nonce); err != nil {
		log.Printf("Error storing token: %v", err)
	}

	newURL := buildConnectURL(t.Config, connectLogoutPath)
	q := newURL.Query()
	q.Set("client_id", t.Config.ClientID)
	q.Set("post_logout_redirect_uri", t.Config.LogoutRedirectURI)
	q.Set("state", nonce)
	newURL.RawQuery = q.Encode()
	http.Redirect(w, r, newURL.String(), http.StatusSeeOther)
}

// This is a callback from the OAuth server
func (t *GoConnect) logoutComplete(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("state")
	// Redirect to the default logout no matter what
	defer http.Redirect(w, r, t.Config.LoginCompleteRedirect, http.StatusSeeOther)
	if nonce != "" {
		if err := t.storage.CheckLogoutNonce(nonce); err != nil {
			// Something is broken.
			return
		}
		// Find the user's session
		cookie, err := r.Cookie(connectIDCookieName)
		if cookie == nil || err != nil {
			// Something is broken. Redirect to logout
			return
		}
		// Delete session and cookie before redirecting
		t.storage.DeleteSession(cookie.Value)
		http.SetCookie(w, &http.Cookie{Name: connectIDCookieName, MaxAge: 0, Expires: time.Now().Add(-1)})
	}
}

type connectHandler struct {
	connect *GoConnect
}

func (c *connectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, c.connect.Config.LoginInit) {
		c.connect.startLogin(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.connect.Config.LoginCallback) {
		c.connect.loginComplete(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.connect.Config.ProfileEndpoint) {
		c.connect.showSessionInfo(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.connect.Config.LogoutInit) {
		c.connect.startLogout(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.connect.Config.LogoutCallback) {
		c.connect.logoutComplete(w, r)
		return
	}
	log.Printf("Got auth request to %s but I don't know how to handle it.", r.URL.Path)
	http.Redirect(w, r, c.connect.Config.LogoutCompleteRedirect, http.StatusSeeOther)
}

// Handler returns a http.Handler for the callback endpoint. This is a set of endpoints that
// the browser is redirected to from the Connect ID OAuth server. The handler will respond
// on the following endpoints:
// <ul>
// <li> <endpoint>/login to start a login roundtrip towards the OAuth server
// <li> <endpoint>/complete for the OAuth callback
// <li> <endpoint>/info for session information
// <li> <endpoint>/logout to log out the currently logged in user
// </ul>
func (t *GoConnect) Handler() http.Handler {
	return &connectHandler{connect: t}
}
