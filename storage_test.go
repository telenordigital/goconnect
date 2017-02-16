package goconnect

import "testing"

func TestNonceStorage(t *testing.T) {
	storage := NewMemoryStorage()
	if err := storage.PutLoginNonce("hello hello"); err != nil {
		t.Fatal("Couldn't put login token")
	}
	if err := storage.CheckLoginNonce("hello hello"); err != nil {
		t.Fatal("Couldn't find the token")
	}

	if err := storage.CheckLoginNonce("The other one"); err == nil {
		t.Fatal("Expected error when querying for another token")
	}

}

func TestSessionStorage(t *testing.T) {
	storage := NewMemoryStorage()
	session := newSession(jwt{}, "access", "refresh", 10)
	if err := storage.PutSession(session); err != nil {
		t.Fatal("Couldn't store session: ", err)
	}
	if _, err := storage.GetSession(session.id); err != nil {
		t.Fatal("Couldn't retrieve session: ", err)
	}

	expiredSession := newSession(jwt{}, "access", "refresh", -1)
	if err := storage.PutSession(expiredSession); err != nil {
		t.Fatal("Couldn't store session: ", err)
	}

	if _, err := storage.GetSession(expiredSession.id); err != errorNoSession {
		t.Fatal("Expected session to have expired but it didn't")
	}
}
