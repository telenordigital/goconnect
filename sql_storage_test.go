package goconnect

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSQLStorage(t *testing.T) {
	db, err := sql.Open("sqlite3", "connect.db?cache=shared&mode=rwc&_foreign_keys=1&_journal_mode=wal")
	defer func() {
		db.Close()
		os.Remove("connect.db")
		os.Remove("connect.db-shm")
		os.Remove("connect.db-wal")
	}()
	if err != nil {
		t.Fatal(err)
	}

	if err := SQLStorePrepare(db); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLStorage(db)
	if err != nil {
		t.Fatal(err)
	}

	nonceStorageTest(store, t)

	sessionStorageTest(store, t)

}
