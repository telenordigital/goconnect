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
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	PutSession(session Session) error

	// GetSession returns the session associated with the session ID.
	GetSession(sessionid string) (Session, error)

	// DeleteSession removes the session
	DeleteSession(sessionid string)

	//UpdateSession updates a session in the backend store
	UpdateSession(Session) error

	// ListSessions lists all of the sessions in the backend store.
	ListSessions() ([]Session, error)
}

// Memory-backed storage. Uses maps and lists. Naïve implementation.
type memoryStorage struct {
	mutex    *sync.Mutex
	nonces   map[string]time.Time
	sessions map[string]Session
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
		sessions: make(map[string]Session),
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

func (m *memoryStorage) ListSessions() ([]Session, error) {
	ret := make([]Session, 0)
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, v := range m.sessions {
		ret = append(ret, v)
	}
	return ret, nil
}

func (m *memoryStorage) UpdateSession(updatedSession Session) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	_, ok := m.sessions[updatedSession.id]
	if !ok {
		return errors.New("unknown session id: " + updatedSession.id)
	}

	m.sessions[updatedSession.id] = updatedSession
	return nil
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
func newSession(jwt jwt, accessToken string, refreshToken string, expires int) Session {
	randomBytes := make([]byte, 64)
	rand.Read(randomBytes)
	newSessionID := hex.EncodeToString(randomBytes)
	return Session{
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
func (m *memoryStorage) PutSession(session Session) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sessions[session.id] = session
	return nil
}

func (m *memoryStorage) GetSession(sessionID string) (Session, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	sess, exists := m.sessions[sessionID]
	if !exists {
		return Session{}, errorNoSession
	}
	if sess.expires < time.Now().Unix() {
		return Session{}, errorNoSession
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
		time.Sleep(sessionCheckInterval * time.Second)
	}
}
