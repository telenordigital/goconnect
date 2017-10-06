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
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// jwtHeader is the JOSE header of the JWT
type jwtHeader struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
}

// connectIDClaims is a user-friendly representation of the claims in the JWT.
type connectIDClaims struct {
	ID                 string   `json:"sub"`                   // The user's Connect ID.
	Name               string   `json:"name"`                  // Name of user. Note that this is unescaped
	Locale             string   `json:"locale"`                // Preferred locale
	Email              string   `json:"email"`                 // The user's email address
	VerifiedEmail      bool     `json:"email_verified"`        // Verified email flag
	Phone              string   `json:"phone_number"`          // The user's primary phone number
	VerifiedPhone      bool     `json:"verified_phone_number"` // Verified phone
	AuthenticatedWith  string   `json:"td_au"`                 // The ID the user is authenticated with. Either phone or email
	AuthenticationTime int64    `json:"auth_time"`             // The time the user is authenticated
	Expires            int64    `json:"exp"`                   // The time the claim expires
	AuthLevel          string   `json:"acr"`                   // Level of authentication (1 = header injected, 2 = password/OTP via SMS)
	Audiences          []string `json:"aud"`                   // Audience (should be set to the client ID)
}

// jwt is a decoded JSON Web Token
type jwt struct {
	Header       jwtHeader
	Claims       connectIDClaims
	MAC          []byte
	SourceHeader string
	SourceClaims string
}

// Strings aren't padded according to base64 requirements. Add padding characters.
func padString(data string) string {
	if l := len(data) % 4; l > 0 {
		return data + strings.Repeat("=", 4-l)
	}
	return data
}

func (j *jwt) verify(keys *jwkSet) error {
	var n big.Int
	var e int
	for _, v := range keys.Keys {
		if v.KeyID == j.Header.KeyID {
			if v.KeyType != "RSA" {
				return errors.New("Can't verify anything but RSA keys")
			}
			nBytes, err := base64.URLEncoding.DecodeString(padString(v.N))
			if err != nil {
				return err
			}
			n.SetBytes(nBytes)

			eBytes, err := base64.URLEncoding.DecodeString(padString(v.E))
			if err != nil {
				return err
			}
			e = int(eBytes[0])<<16 + int(eBytes[1])<<8 + int(eBytes[0])
		}
	}
	if n.BitLen() == 0 {
		return fmt.Errorf("Could not find an appropriate key (%s) in JWK", j.Header.KeyID)
	}
	if j.Header.Algorithm != "RS256" {
		return errors.New("I'm only able to verify signatures with the RS256 algorithm")
	}
	m := crypto.SHA256.New()
	m.Write([]byte(j.SourceHeader + "." + j.SourceClaims))
	calculatedMAC := m.Sum(nil)
	key := &rsa.PublicKey{N: &n, E: e}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, calculatedMAC, j.MAC); err != nil {
		return errors.New("MAC does not match the computed hash")

	}
	return nil
}

// Check if a string is in an array
func indexOf(arr []string, s string) int {
	for i, v := range arr {
		if v == s {
			return i
		}
	}
	return -1
}

// newJWT creates a new JWT instance from the specified string. The string is encoded
// according to RFC7519.
func newJWT(data string, jwk *jwkSet, config ClientConfig) (jwt, error) {
	jwt := jwt{}

	parts := strings.Split(data, ".")
	if len(parts) != 3 {
		return jwt, errors.New("This is not a valid JWT encoded string. Expected three parts")
	}
	jwt.SourceHeader = parts[0]
	jwt.SourceClaims = parts[1]
	bytes, err := base64.URLEncoding.DecodeString(padString(parts[0]))
	if err != nil {
		return jwt, fmt.Errorf("Eror decoding JOSE Header: %v", err)
	}
	err = json.Unmarshal(bytes, &jwt.Header)
	if err != nil {
		return jwt, fmt.Errorf("Error unmarshaling JSON in header: %s", err)
	}

	// Invariant: Header decoded. Decode claims
	bytes, err = base64.URLEncoding.DecodeString(padString(parts[1]))
	if err != nil {
		return jwt, fmt.Errorf("Error decoding JWT claims: %v", err)
	}
	err = json.Unmarshal(bytes, &jwt.Claims)
	if err != nil {
		return jwt, fmt.Errorf("Error decoing claims section: %v", err)
	}
	bytes, err = base64.URLEncoding.DecodeString(padString(parts[2]))
	if err != nil {
		return jwt, fmt.Errorf("Error decoding MAC: %v", err)
	}
	jwt.MAC = bytes

	// Verify sanity of claim by inspecting fields (http://docs.telenordigital.com/connect/id/id_token.html)
	if indexOf(jwt.Claims.Audiences, config.ClientID) < 0 {
		// Invalid claim
		return jwt, errors.New("JWT does not contain the expected audience")
	}
	if jwt.Claims.Expires < jwt.Claims.AuthenticationTime {
		// expires before the authentication
		return jwt, errors.New("JWT expires before authentication time")
	}

	// Verify signature
	if err := jwt.verify(jwk); err != nil {
		return jwt, fmt.Errorf("Could not verify JWT: %v", err)
	}

	return jwt, nil
}
