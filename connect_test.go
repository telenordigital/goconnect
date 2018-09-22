// build +testlocally
package goconnect

import (
	"net/http"
	"testing"
	"time"
)

// This is a simplified test that just launches loging and logout flows.
func TestConnectLogin(t *testing.T) {
	config := NewDefaultConfig(ClientConfig{
		Host:                      StagingHost,
		ClientID:                  "telenordigital-connectexample-web",
		Password:                  "",
		LoginCompleteRedirectURI:  "/",
		LogoutCompleteRedirectURI: "/",
	})

	connect := NewConnectID(config)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello hello"))
	})
	http.Handle("/connect/", connect.Handler())

	// Show the logged in user's properties.
	http.HandleFunc("/connect/profile", connect.SessionProfile)

	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			t.Fatal(err)
		}
	}()

	client := http.Client{}
	resp, err := client.Get("http://localhost:8080/connect/login")
	if err != nil {
		t.Fatal("Got error calling login: ", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal("Got status ", resp.Status)
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		t.Logf("Redirect: %+v", req)
		return nil
	}
	resp, err = client.Get("http://localhost:8080/connect/logout")
	if err != nil {
		t.Fatal("Got error calling logout: ", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Got response %+v", resp)
	}
}

func TestTokenRefresh(t *testing.T) {
	config := NewDefaultConfig(ClientConfig{
		Host:                      StagingHost,
		ClientID:                  "telenordigital-connectexample-web",
		Password:                  "",
		LoginCompleteRedirectURI:  "/",
		LogoutCompleteRedirectURI: "/",
	})

	connect := NewConnectID(config)
	connect.storage.PutSession(Session{
		id:           "1",
		accessToken:  "foo",
		refreshToken: "bar",
		expires:      time.Now().Add(-time.Hour).Unix(),
		UserID:       "1",
	})
	refreshTokens(connect.storage, connect.Config, 1)
}
