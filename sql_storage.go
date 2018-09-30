package goconnect

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"
)

// SQLSchema contains DDL statements for the backend store. The statements works
// on both SQLite and PostgreSQL. They must be executed in the order they are
// returned.
var SQLSchema = []string{
	`CREATE TABLE sessions (
		session_id VARCHAR(128) NOT NULL,
		session_data TEXT,
		expires BIGINT NOT NULL,
		CONSTRAINT sessions_pk PRIMARY KEY (session_id))`,
	"CREATE INDEX sessions_expired ON sessions(expires)",
	`CREATE TABLE nonces (
		nonce VARCHAR(128) NOT NULL,
		created BIGINT NOT NULL,
		type SMALLINT NOT NULL,
		CONSTRAINT nonces_pk PRIMARY KEY (nonce))`,
	"CREATE INDEX nonces_created ON nonces(created)",
	"CREATE INDEX nonces_type ON nonces(type)",
}

// Interval between nonce and session cleanups
const cleanupIntervalSeconds = 30

type sqlStorage struct {
	db                   *sql.DB
	deleteExpiredNonce   *sql.Stmt
	deleteExpiredSession *sql.Stmt
	updateSession        *sql.Stmt
	insertSession        *sql.Stmt
	removeNonce          *sql.Stmt
	checkLoginNonce      *sql.Stmt
	checkLogoutNonce     *sql.Stmt
	insertNonce          *sql.Stmt
	retrieveSession      *sql.Stmt
	removeSession        *sql.Stmt
	listSessions         *sql.Stmt
	expireNonces         *sql.Stmt
}

// NewSQLStorage creates a new SQL-backed storage
func NewSQLStorage(db *sql.DB) (Storage, error) {
	if db == nil {
		return nil, errors.New("DB parameter must be set")
	}

	ret := sqlStorage{db: db}
	var err error
	if ret.deleteExpiredNonce, err = db.Prepare(`
		DELETE FROM nonces WHERE created < $1
		`); err != nil {
		return nil, err
	}
	if ret.deleteExpiredSession, err = db.Prepare(`
		DELETE FROM sessions WHERE expires < $1
		`); err != nil {
		return nil, err
	}
	if ret.updateSession, err = db.Prepare(`
		UPDATE sessions SET session_data = $1, expires = $2 WHERE session_id = $3
		`); err != nil {
		return nil, err
	}
	if ret.insertSession, err = db.Prepare(`
		INSERT INTO sessions (session_id, session_data, expires) VALUES ($1, $2, $3)
		`); err != nil {
		return nil, err
	}
	if ret.removeNonce, err = db.Prepare(`DELETE FROM nonces WHERE nonce = $1`); err != nil {
		return nil, err
	}
	// In theory the next two statements could be just a single statement
	// but using explicit values makes the query planner happier
	if ret.checkLoginNonce, err = db.Prepare(`
		SELECT nonce
		FROM nonces
		WHERE type = 1 AND nonce = $1 AND created > $2
		`); err != nil {
		return nil, err
	}
	if ret.checkLogoutNonce, err = db.Prepare(`
		SELECT nonce
		FROM nonces
		WHERE type = 2 AND nonce = $1 AND created > $2
		`); err != nil {
		return nil, err
	}
	if ret.insertNonce, err = db.Prepare(`
		INSERT INTO nonces (nonce, created, type) VALUES ($1, $2, $3)
		`); err != nil {
		return nil, err
	}
	if ret.retrieveSession, err = db.Prepare(`
		SELECT session_id, expires, session_data FROM sessions WHERE session_id = $1 AND expires >= $2
		`); err != nil {
		return nil, err
	}
	if ret.removeSession, err = db.Prepare(`
		DELETE FROM sessions WHERE session_id = $1
		`); err != nil {
		return nil, err
	}
	if ret.listSessions, err = db.Prepare(`
		SELECT session_id, expires, session_data FROM sessions
		`); err != nil {
		return nil, err
	}
	if ret.expireNonces, err = db.Prepare(`
		DELETE from nonces WHERE created < $1
	`); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (s *sqlStorage) sessionAndNonceRemover() {
	for {
		// Nonces are at most 20 minutes old
		expire := time.Now().Add(-20 * time.Minute).Unix()
		if _, err := s.deleteExpiredNonce.Exec(expire); err != nil {
			log.Printf("Got error removing nonces: %v", err)
		}

		if _, err := s.deleteExpiredSession.Exec(time.Now().Unix()); err != nil {
			log.Printf("Got error removing sessions: %v", err)
		}
		time.Sleep(cleanupIntervalSeconds * time.Second)
	}
}

func (s *sqlStorage) PutLoginNonce(token string) error {
	result, err := s.insertNonce.Exec(token, time.Now().Unix(), 1)
	if err != nil {
		log.Printf("Unable to create login nonce: %v", err)
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count == 0 {
		log.Printf("%d rows inserted for login nonce: %v", count, err)
	}
	return nil
}

func (s *sqlStorage) checkNonce(token string, stmt *sql.Stmt) error {
	expired := time.Now().Add(-20 * time.Minute).Unix()
	result, err := stmt.Query(token, expired)
	if err != nil {
		log.Printf("Unable to retrieve nonce count: %v", err)
		return err
	}
	defer result.Close()
	if !result.Next() {
		return fmt.Errorf("Unknown nonce: \"%s\"", token)
	}
	_, err = s.removeNonce.Exec(token)
	if err != nil {
		log.Printf("Unable to remove nonce %s: %v", token, err)
		return err
	}
	return nil
}

func (s *sqlStorage) CheckLoginNonce(token string) error {
	return s.checkNonce(token, s.checkLoginNonce)
}

func (s *sqlStorage) PutLogoutNonce(token string) error {
	if _, err := s.insertNonce.Exec(token, time.Now().Unix(), 2); err != nil {
		log.Printf("Unable to insert nonce: %v", err)
		return err
	}
	return nil
}

func (s *sqlStorage) CheckLogoutNonce(token string) error {
	return s.checkNonce(token, s.checkLogoutNonce)
}

// Use a custom session struct to include the private fields in the
// exported struct
type dbSession struct {
	ID           string `json:"sessionID"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	Expires      int64  `json:"expires"`

	Session Session `json:"session"`
}

func dbSessionFromSession(sess Session) dbSession {
	return dbSession{
		ID:           sess.id,
		AccessToken:  sess.accessToken,
		RefreshToken: sess.refreshToken,
		Expires:      sess.expires,
		Session:      sess}
}

func sessionFromDBSession(db dbSession) Session {
	ret := db.Session
	ret.id = db.ID
	ret.accessToken = db.AccessToken
	ret.refreshToken = db.RefreshToken
	ret.expires = db.Expires
	return ret
}

func (s *sqlStorage) PutSession(session Session) error {
	dbs := dbSessionFromSession(session)
	data, err := json.Marshal(&dbs)
	if err != nil {
		return err
	}
	if _, err := s.insertSession.Exec(session.id, data, session.expires); err != nil {
		log.Printf("Unable to insert session: %v", err)
		return err
	}
	return nil
}

func (s *sqlStorage) GetSession(sessionid string) (Session, error) {
	result, err := s.retrieveSession.Query(sessionid, time.Now().Unix())
	if err != nil {
		log.Printf("Unable to query for session %s: %v", sessionid, err)
		return Session{}, err
	}
	defer result.Close()
	if result.Next() {
		var data []byte
		var sessionID string
		var expires int64
		if err := result.Scan(&sessionID, &expires, &data); err != nil {
			log.Printf("Unable to read session %s rom db: %v", sessionid, err)
			return Session{}, err
		}
		dbs := dbSession{}
		if err = json.Unmarshal(data, &dbs); err != nil {
			return Session{}, err
		}
		return sessionFromDBSession(dbs), nil
	}
	return Session{}, errorNoSession
}

func (s *sqlStorage) DeleteSession(sessionid string) {
	if _, err := s.removeSession.Exec(sessionid); err != nil {
		log.Printf("Unable to remove session %s: %v", sessionid, err)
	}
}

func (s *sqlStorage) UpdateSession(session Session) error {
	dbs := dbSessionFromSession(session)
	data, err := json.Marshal(&dbs)
	if err != nil {
		return err
	}
	_, err = s.updateSession.Exec(data, session.expires, session.id)
	return err
}

func (s *sqlStorage) ListSessions() ([]Session, error) {
	ret := make([]Session, 0)
	result, err := s.listSessions.Query()
	if err != nil {
		return ret, err
	}

	defer result.Close()
	for result.Next() {
		var data []byte
		var sessionID string
		var expires int64
		if err := result.Scan(&sessionID, &expires, &data); err != nil {
			log.Printf("Unable to scan result: %v", err)
			return ret, err
		}
		dbs := dbSession{}
		json.Unmarshal(data, &dbs)
		ret = append(ret, sessionFromDBSession(dbs))
	}
	return ret, nil
}

// SQLStorePrepare runs the DDL statements on the database.
func SQLStorePrepare(db *sql.DB) error {
	for _, stmt := range SQLSchema {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqlStorage) RemoveExpiredNonces() {
	expires := time.Now().Unix() - nonceTimeoutSeconds
	if _, err := s.expireNonces.Exec(expires); err != nil {
		log.Printf("Unable to expired nonces: %v", err)
	}
}
