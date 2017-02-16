package goconnect

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

var (
	// ErrorNonceExists is returned when the nonce already exists
	errorNonceExists = errors.New("Nonce already exists")

	// ErrorNonceExpired is returned if the nonce exists but has expired
	errorNonceExpired = errors.New("Nonce has expired")

	// ErrorNoNonce is returned if the nonce doesn't exist
	errorNoNonce = errors.New("Nonce does not exist")

	// ErrorNoSession is returned when the session isn't found
	errorNoSession = errors.New("No such session")
)

// This is the default nonce timeout.
const nonceTimeout time.Duration = 5 * time.Minute

// Storage is the session and nonce storage used by the go-connectid client.
// The default session and nonce storage is memory-based. It works perfectly fine
// for a single-server installation but if you run more than one server you probably
// want to use a different backend such as Memcached or Redis for session storage.
//
// The storage implementation is responsible for expiring nonces automatically.
// RefreshTokens is used to refresh access tokens against the OAuth server.
type Storage interface {
	// Add state nonce to storage. This is disposable and will expire in 20 minutes
	PutLoginNonce(token string) error

	// Retrieve and remove nonce (if it exists) from storage
	CheckLoginNonce(token string) error

	// Add state nonce to storage. This is disposable and will expire in 20 minutes
	PutLogoutNonce(token string) error

	// Retrieve and remove nonce (if it exists) from storage
	CheckLogoutNonce(token string) error

	// PutSession creates a new session identifier and stores
	// the information in a session structure
	PutSession(session *Session) error

	// GetSession returns the session associated with the session ID.
	GetSession(sessionid string) (*Session, error)

	// DeleteSession removes the session
	DeleteSession(sessionid string)

	// RefreshTokens does a token refresh on all tokens that are about to
	// expire. If the token fails to refresh the session will be invalidated.
	RefreshTokens(config ClientConfig, lookahead time.Duration)
}

// Memory-backed storage. Uses maps and lists. Naïve implementation.
type memoryStorage struct {
	mutex    *sync.Mutex
	nonces   map[string]time.Time
	sessions map[string]*Session
}

// NewMemoryStorage creates a new memory-backed storage implementation. This implementation
// is suitable for single-server solution. If you are running on more than one server
// this must be implemented as a common storage, ie. in some sort of database. The
// stored data is just nonces and sessions so data integrity isn't the most critical
// aspect. A storage backed by Memcached or Redis would be ideal for this.
func NewMemoryStorage() Storage {
	storage := &memoryStorage{
		mutex:    &sync.Mutex{},
		nonces:   make(map[string]time.Time),
		sessions: make(map[string]*Session),
	}
	go storage.sessionChecker()
	return storage
}

func (m *memoryStorage) putNonce(token string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	_, exists := m.nonces[token]
	if exists {
		return errorNonceExists
	}
	m.nonces[token] = time.Now().Add(nonceTimeout)
	return nil
}

func (m *memoryStorage) checkNonce(token string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	timestamp, exists := m.nonces[token]
	if !exists {
		return errorNoNonce
	}
	// Invariant: Token exists
	delete(m.nonces, token)
	if timestamp.Before(time.Now()) {
		return errorNonceExpired
	}
	return nil
}

func (m *memoryStorage) PutLoginNonce(token string) error {
	return m.putNonce(token)
}

func (m *memoryStorage) CheckLoginNonce(token string) error {
	return m.checkNonce(token)
}

func (m *memoryStorage) PutLogoutNonce(token string) error {
	return m.putNonce(token)
}

func (m *memoryStorage) CheckLogoutNonce(token string) error {
	return m.checkNonce(token)
}

// Session holds the session information from the CONNECT ID OAuth server.
type Session struct {
	id           string // The session ID
	accessToken  string // The access token - will be refreshed
	refreshToken string // OAuth refresh token
	expires      int64  // Access token expire time

	UserID        string `json:"connect_id"`     // Connect ID
	Name          string `json:"name"`           // Name (might be blank)
	Locale        string `json:"locale"`         // Locale (might be blank)
	Email         string `json:"email"`          // Email (might be blank)
	VerifiedEmail bool   `json:"verified_email"` // Email is verified
	Phone         string `json:"phone"`          // Phone # (might be blank)
	VerifiedPhone bool   `json:"verified_phone"` // Verified phone
}

// newSession creates a new session
func newSession(jwt jwt, accessToken string, refreshToken string, expires int) *Session {
	randomBytes := make([]byte, 64)
	rand.Read(randomBytes)
	newSessionID := hex.EncodeToString(randomBytes)
	return &Session{
		id:            newSessionID,
		UserID:        jwt.Claims.ID,
		Name:          jwt.Claims.Name,
		Locale:        jwt.Claims.Locale,
		Email:         jwt.Claims.Email,
		VerifiedEmail: jwt.Claims.VerifiedEmail,
		Phone:         jwt.Claims.Phone,
		VerifiedPhone: jwt.Claims.VerifiedPhone,
		accessToken:   accessToken,
		refreshToken:  refreshToken,
		expires:       time.Now().Add(time.Duration(expires) * time.Second).Unix(),
	}
}
func (m *memoryStorage) PutSession(session *Session) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sessions[session.id] = session
	return nil
}

func (m *memoryStorage) GetSession(sessionID string) (*Session, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	sess, exists := m.sessions[sessionID]
	if !exists {
		return nil, errorNoSession
	}
	if sess.expires < time.Now().Unix() {
		return nil, errorNoSession
	}
	return sess, nil
}

func (m *memoryStorage) DeleteSession(sessionID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.sessions, sessionID)
}

const sessionCheckInterval = 10

// The session checker checks if the access token is about to expire and if it is
// the refresh token will be used to create a new. If the operation fails the session
// will be removed.
func (m *memoryStorage) sessionChecker() {
	for {
		m.mutex.Lock()
		for sessionID, v := range m.sessions {
			if v.expires < time.Now().Unix() {
				delete(m.sessions, sessionID)
			}
		}
		for nonce, expires := range m.nonces {
			if time.Now().After(expires) {
				delete(m.nonces, nonce)
			}
		}
		m.mutex.Unlock()
		<-time.After(sessionCheckInterval * time.Second)
	}
}

// Refresh the access token for a session.
func (m *memoryStorage) refreshAccessToken(config ClientConfig, session *Session) {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Printf("Got error doing request for session %s: (status=%d) %v", session.id, resp.StatusCode, err)
		return
	}
	// Invariant: Request is OK, read body of response
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Got error reading response body when refreshing session %s: %v", session.id, err)
		return
	}
	// Invariant: Body is read, response OK, unmarshal it into struct
	tokens := tokenResponse{}
	if err := json.Unmarshal(buf, &tokens); err != nil {
		log.Printf("Got error unmarshaling response body when refreshing session %s: %v", session.id, err)
		return
	}

	// Invariant: Response OK and read. Update session
	m.mutex.Lock()
	defer m.mutex.Unlock()
	updatedSession := Session{
		id:            session.id,
		accessToken:   tokens.AccessToken,
		refreshToken:  tokens.RefreshToken,
		expires:       time.Now().Add(time.Duration(tokens.AccessTokenExpires) * time.Second).Unix(),
		UserID:        session.UserID,
		Name:          session.Name,
		Locale:        session.Locale,
		Email:         session.Email,
		VerifiedEmail: session.VerifiedEmail,
		Phone:         session.Phone,
		VerifiedPhone: session.VerifiedPhone,
	}
	m.sessions[updatedSession.id] = &updatedSession
}

func (m *memoryStorage) RefreshTokens(config ClientConfig, lookAhead time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for _, session := range m.sessions {
		// Make sure the session check doesn't nuke the session before it can be refreshed.
		// The session check interval is assumed to be a lot shorter than the session length.
		// Check for 2x the session check interval just to be sure.
		if (session.expires + 2*sessionCheckInterval) < time.Now().Add(lookAhead).Unix() {
			go m.refreshAccessToken(config, session)
		}
	}
}
