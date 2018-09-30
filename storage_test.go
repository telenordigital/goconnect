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
	"testing"
	"time"
)

func nonceStorageTest(storage Storage, t *testing.T) {
	if err := storage.PutLoginNonce("hello hello"); err != nil {
		t.Fatal("Couldn't put login token: ", err)
	}
	if err := storage.CheckLoginNonce("hello hello"); err != nil {
		t.Fatal("Couldn't find the token: ", err)
	}
	if err := storage.CheckLoginNonce("hello hello"); err == nil {
		t.Fatal("Nonce 1 should be gone")
	}
	if err := storage.CheckLoginNonce("The other one"); err == nil {
		t.Fatal("Expected error when querying for another token")
	}

	if err := storage.PutLogoutNonce("hello hello 2"); err != nil {
		t.Fatal("Couldn't put login token: ", err)
	}
	if err := storage.CheckLogoutNonce("hello hello 2"); err != nil {
		t.Fatal("Couldn't find the token: ", err)
	}
	if err := storage.CheckLogoutNonce("hello hello 2"); err == nil {
		t.Fatal("Nonce 2 should be gone ")
	}

}

func sessionStorageTest(storage Storage, t *testing.T) {
	session := newSession(jwt{}, "access", "refresh", 10)
	if err := storage.PutSession(session); err != nil {
		t.Fatal("Couldn't store session: ", err)
	}
	if _, err := storage.GetSession(session.id); err != nil {
		t.Fatal("Couldn't retrieve session: ", err)
	}

	expiredSession := newSession(jwt{}, "access", "refresh", -10)
	if err := storage.PutSession(expiredSession); err != nil {
		t.Fatal("Couldn't store session: ", err)
	}

	if _, err := storage.GetSession(expiredSession.id); err != errorNoSession {
		t.Fatal("Expected session to have expired but it didn't (err = ", err, ")")
	}

	session.accessToken = "access2"
	session.refreshToken = "refresh"
	session.expires = time.Now().Unix() + int64(time.Second/time.Nanosecond)

	if err := storage.UpdateSession(session); err != nil {
		t.Fatal("Couldn't update session: ", err)
	}

	sessions, err := storage.ListSessions()
	if err != nil {
		t.Fatal("Couldn't list sessions: ", err)
	}
	if len(sessions) == 0 {
		t.Fatalf("Found %d sessions, expected > 0", len(sessions))
	}
	for _, v := range sessions {
		if v.id == "" || v.accessToken == "" || v.refreshToken == "" {
			t.Fatal("Invalid token from list")
		}
	}
	storage.DeleteSession(sessions[0].id)
}

func TestNonceStorage(t *testing.T) {
	storage := NewMemoryStorage()
	nonceStorageTest(storage, t)

}

func TestSessionStorage(t *testing.T) {
	storage := NewMemoryStorage()
	sessionStorageTest(storage, t)
}
