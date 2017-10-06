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
import "testing"

const connectTestData = `eyJraWQiOiIxIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1OTg0MzU1Nzg2MTAzNDYzOTM2IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImFtciI6WyJVSURfUFdEIl0sImlzcyI6Imh0dHBzOlwvXC9jb25uZWN0LnN0YWdpbmcudGVsZW5vcmRpZ2l0YWwuY29tXC9vYXV0aCIsInBob25lX251bWJlcl92ZXJpZmllZCI6ZmFsc2UsInRkX3NscyI6ZmFsc2UsImxvY2FsZSI6ImVuIiwiYWNyIjoiMiIsImF1ZCI6WyJ0ZWxlbm9yZGlnaXRhbC1sb3JhY29yZS13ZWIiXSwidGRfYXUiOiI0NzkyNDA0NjEwIiwiYXV0aF90aW1lIjoxNDg3NjA2NTQ3LCJuYW1lIjoiU3TDpWxlIEZvbyDwn5iA8J-YgfCfmIgiLCJwaG9uZV9udW1iZXIiOiI0NzkyNDA0NjEwIiwiZXhwIjoxNDg3NjEwNDQ3LCJpYXQiOjE0ODc2MDY1NDcsImVtYWlsIjoic3RhbGVoZCtmb29iYXJiYXpAY29tb3lvLmNvbSJ9.boOztuLNDIdLnO_YDvxtMQM37wWPhJDqi3UF-CvUfpflFZ0flZHxAQ0lCyqecJDoHw72EM3rlXy95w4lMThDPXyFvsw_2zmSQTar9gK03W12JuLPsfEP9Oo4NHwHkYKpEr5pfoLYIbwOMJxTx-j9VQ_9jmdbdbezE2TdHlzwgpg`

const rfcTestData = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func TestInvalidJWTData(t *testing.T) {
	config := NewDefaultConfig(ClientConfig{Host: StagingHost})
	jwk := jwkSet{}

	var err error
	_, err = newJWT("", &jwk, config)
	if err == nil {
		t.Fatal("Expected error when using blank token")
	}
	_, err = newJWT("aaa", &jwk, config)
	if err == nil {
		t.Fatal("Expected error when using invalid base64")
	}
	_, err = newJWT("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", &jwk, config)
	if err == nil {
		t.Fatal("Expected error when using just one field")
	}
	_, err = newJWT("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", &jwk, config)
	if err == nil {
		t.Fatal("Expected error when using just two fields")
	}
	_, err = newJWT("...", &jwk, config)
	if err == nil {
		t.Fatal("Expected error when using empty fields")
	}
}

func TestConnectIDJWT(t *testing.T) {
	config := NewDefaultConfig(ClientConfig{Host: StagingHost, ClientID: "telenordigital-loracore-web"})
	url := buildConnectURL(config, connectJWKPath)
	cache := newJWKCache(url.String())
	jwk, err := cache.GetJWK()
	if err != nil {
		t.Fatal("Could not retrieve JWK: ", err)
	}

	_, err = newJWT(connectTestData, jwk, config)
	if err != nil {
		t.Fatal("Could not create token from string: ", err)
	}
	//fmt.Println(jwt)

}
