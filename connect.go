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
import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// NewConnectID creates a new ConnectID client usign the default (memory-based)
// storage.
func NewConnectID(config ClientConfig) *GoConnect {
	return NewConnectIDWithStorage(config, NewMemoryStorage())
}

// NewConnectIDWithStorage creates a new ConnectID client with the specified
// storage implementation.
func NewConnectIDWithStorage(config ClientConfig, storage Storage) *GoConnect {
	jwkURL := buildConnectURL(config, connectJWKPath)
	client := &GoConnect{
		Config:   config,
		storage:  storage,
		jwkCache: newJWKCache(jwkURL.String()),
		mutex:    &sync.Mutex{},
	}
	go client.tokenRefresher()
	return client
}

func refreshAccessToknes(storage Storage, config ClientConfig, session Session) {
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", session.refreshToken)
	params.Set("client_id", config.ClientID)
	formData := params.Encode()
	refreshURL := buildConnectURL(config, connectTokenPath)
	req, err := http.NewRequest("POST", refreshURL.String(), bytes.NewBufferString(formData))
	if err != nil {
		log.Printf("Got error creating refresh request for session %s. Won't refresh access token: %v", session.id, err)
		return
	}
	req.SetBasicAuth(config.ClientID, config.Password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(formData)))
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Got error doing request for session %s: %v", session.id, err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Got status %d doing request for session %s.", resp.StatusCode, session.id)
		return
	}
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		log.Printf("Got error decoding response body when refreshing session %s: %v", session.id, err)
		return
	}

	// Invariant: Response OK and read. Update session
	expires := time.Now().Unix() + int64(tokens.AccessTokenExpires)
	updatedSession := Session{
		id:            session.id,
		accessToken:   tokens.AccessToken,
		refreshToken:  tokens.RefreshToken,
		expires:       expires, // ,
		UserID:        session.UserID,
		Name:          session.Name,
		Locale:        session.Locale,
		Email:         session.Email,
		VerifiedEmail: session.VerifiedEmail,
		Phone:         session.Phone,
		VerifiedPhone: session.VerifiedPhone,
	}
	if err := storage.UpdateSession(updatedSession); err != nil {
		log.Printf("Unable to update session %v: %v", updatedSession.id, err)
	}
}

func refreshTokens(storage Storage, config ClientConfig, lookAheadSeconds int) {
	list, err := storage.ListSessions()
	if err != nil {
		log.Printf("Unable to list sessions: %v. Sessions won't be updated.", err)
		return
	}
	for _, session := range list {
		timeToExpire := session.expires - time.Now().Unix()
		if timeToExpire < (int64(lookAheadSeconds) * 2) {
			// Make sure the session check doesn't nuke the session before it can be refreshed.
			// The session check interval is assumed to be a lot shorter than the session length.
			// Check for 2x the session check interval just to be sure.
			refreshAccessToknes(storage, config, session)
		}
		if timeToExpire < 0 {
			log.Printf("Removing session %s from storage -- expired at %d", session.id, session.expires)
			storage.DeleteSession(session.id)
		}
	}
}

const sessionRefreshInterval = 30

func (t *GoConnect) tokenRefresher() {
	const sleepTime = time.Second * sessionRefreshInterval
	for {
		time.Sleep(sleepTime)
		refreshTokens(t.storage, t.Config, sessionRefreshInterval)
		t.storage.RemoveExpiredNonces()
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
	q.Set("scope", DefaultScopes)
	q.Set("acr_values", "2")
	q.Set("redirect_uri", t.Config.LoginRedirectURI)
	q.Set("state", loginToken)
	newURL.RawQuery = q.Encode()

	// Remove any old session cookie before starting the roundtrip.
	http.SetCookie(w, &http.Cookie{
		Name:     connectIDCookieName,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   t.Config.UseSecureCookie,
		Path:     "/",
	})

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
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nothing, fmt.Errorf("Could not decode response: %v", err)
	}
	return tokens, nil
}

// Handle the redirect from the OAuth server when login is complete.
func (t *GoConnect) loginComplete(w http.ResponseWriter, r *http.Request) {
	// Login is complete - check that code matches the state parameter sent earlier. States
	// are kept for N hours? Mismatch => error page saying "try again"
	// obtain tokens, store token and set cookie
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Verify that state is sent previously
	if err := t.storage.CheckLoginNonce(state); err != nil {
		http.Error(w, "Unknown state token. Your login session might have timed out.", http.StatusBadRequest)
		return
	}

	errcode := r.URL.Query().Get("error")
	if errcode != "" {
		// There's an error message. Just redirect back to the logout page.
		log.Printf("Got error from OAuth server: %s - %s", errcode, r.URL.Query().Get("error_description"))
		http.Redirect(w, r, t.Config.LogoutCompleteRedirectURI, http.StatusSeeOther)
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
		Expires:  time.Now().Add(48 * time.Hour),
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, t.Config.LoginCompleteRedirectURI, http.StatusSeeOther)
}

// Check if there is a session. Set error and return otherwise
func (t *GoConnect) isAuthorized(w http.ResponseWriter, r *http.Request) (bool, Session) {
	cookie, err := r.Cookie(connectIDCookieName)
	if cookie == nil || err == http.ErrNoCookie {
		http.Error(w, "You are not authorized to view this page. Try logging in again.", http.StatusUnauthorized)
		return false, Session{}
	}
	session, err := t.storage.GetSession(cookie.Value)
	if err == errorNoSession {
		http.Error(w, "You are not authorized to view this page. Try logging in again.", http.StatusUnauthorized)
		return false, Session{}
	}

	return true, session
}

// SessionProfile is a premade session endpoint that you can use to serve the
// profile information to the end user. Since this resource might be used
// by JavaScript clients it would potentially need CORS headers and a matching
// OPTIONS header but this might introduce security issues. Add the header
// to the default mux by using the following snippet:
//
//     http.HandleFunc("/connect/profile", connect.SessionProfile)
//
func (t *GoConnect) SessionProfile(w http.ResponseWriter, r *http.Request) {
	auth, session := t.isAuthorized(w, r)
	if !auth {
		return
	}
	if err := json.NewEncoder(w).Encode(session); err != nil {
		log.Printf("Got error encoding session to JSON: %v", err)
		http.Error(w, "Session read error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
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

// Handle the redirect from the OAuth server when the logout is complete.
func (t *GoConnect) logoutComplete(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("state")
	// Redirect to the default logout no matter what
	defer http.Redirect(w, r, t.Config.LogoutCompleteRedirectURI, http.StatusSeeOther)
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
	if strings.HasSuffix(r.URL.Path, c.connect.Config.LoginRedirect) {
		c.connect.loginComplete(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.connect.Config.LogoutInit) {
		c.connect.startLogout(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, c.connect.Config.LogoutRedirect) {
		c.connect.logoutComplete(w, r)
		return
	}
	log.Printf("Got auth request to %s but I don't know how to handle it.", r.URL.Path)
	http.Redirect(w, r, c.connect.Config.LogoutCompleteRedirectURI, http.StatusSeeOther)
}

// Handler returns a http.Handler that will respond on the following endpoints:
//
//   Config.LoginInit to start a login roundtrip towards the OAuth server
//   Config.LoginRedirect for the OAuth redirect when login is complete
//   Config.LogoutInit to start a logout roundtrip towards the OAuth server
//   Config.LogoutRedirect for the OAuth redirect when logout is complete
//
// The Init endpoints are the ones you navigate to to initiate the action.
// The Redirect endpoints are redirected to from the OAuth server when it is complete.
func (t *GoConnect) Handler() http.Handler {
	return &connectHandler{connect: t}
}
