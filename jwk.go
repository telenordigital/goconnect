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
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"
)

// JWK is a single JSON Web Key
type jwk struct {
	KeyType      string `json:"kty"`
	PublicKeyUse string `json:"use"`
	Algorithm    string `json:"alg"`
	KeyID        string `json:"kid"`
	N            string `json:"n"`
	E            string `json:"e"`
}

// JWKSet is the set of JSON Web Keys exposed by the Connect ID OAuth endpoint.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// JWKCache caches the JWKs from the OAuth server. It will
// retrieve new keys every 60 minutes.
type jwkCache struct {
	jwks    *jwkSet
	mutex   *sync.Mutex
	expires time.Time
	url     string
}

// GetJWK returns the JWK from the OAuth server. The value is cached for
// 60 minutes
func (j *jwkCache) GetJWK() (*jwkSet, error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	if j.jwks == nil || time.Now().After(j.expires) {
		set := jwkSet{}
		resp, err := http.Get(j.url)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Expected 200 OK but got %d from Connect OAuth server (%s)", resp.StatusCode, j.url)
			return nil, errors.New("Could not retrieve JWK from Connect servers")
		}
		if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
			log.Printf("Got error decoding response: %v", err)
			return nil, err
		}
		j.jwks = &set
		j.expires = time.Now().Add(60 * time.Minute)
	}
	return j.jwks, nil
}

// Create a new cache object
func newJWKCache(url string) *jwkCache {
	return &jwkCache{
		url:   url,
		mutex: &sync.Mutex{},
		jwks:  nil,
	}
}
