package goconnect

import (
	"testing"
	"time"
)

func TestJWKCache(t *testing.T) {
	// Nothing fancy, just run through the entire process
	config := ClientConfig{Host: StagingHost}
	url := buildConnectURL(config, connectJWKPath)

	cache := newJWKCache(url.String())

	jwk, err := cache.GetJWK()
	if err != nil {
		t.Fatal("Got error retrieving cached JWK")
	}

	if jwk == nil {
		t.Fatal("Did not get a valid JWK")
	}
	// fake expired jwk
	cache.expires = time.Now()

	jwk, err = cache.GetJWK()
	if err != nil {
		t.Fatal("Got error retrieving cached JWK")
	}

	if jwk == nil {
		t.Fatal("Did not get a valid JWK")
	}

}
