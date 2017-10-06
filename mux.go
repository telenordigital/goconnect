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
	"context"
	"net/http"
)

type contextKey string

const (
	// SessionContext is the identifier for the http.Request context. Use this to access the
	// session object when the NewHandlerFunc has wrapped a HandlerFunc.
	SessionContext contextKey = "connect-session"
)

// NewAuthHandlerFunc returns a http.HandlerFunc that requires authentication. If
// the request isn't authenticated a 401 Unauthorized is returned, otherwise the
// existing http.HandlerFunc will be called as normal. The session object is
// passed along in the request's Context object.
func (t *GoConnect) NewAuthHandlerFunc(existingFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// Pass on the request and use an empty session object.
			sessionContext := context.WithValue(r.Context(), SessionContext, Session{})
			existingFunc(w, r.WithContext(sessionContext))
			return
		}
		auth, session := t.isAuthorized(w, r)
		if !auth {
			return
		}
		sessionContext := context.WithValue(r.Context(), SessionContext, session)
		existingFunc(w, r.WithContext(sessionContext))
	}
}

type authHandler struct {
	connect         *GoConnect
	existingHandler http.Handler
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		// Pass on to existing handler but include empty session object
		sessionContext := context.WithValue(r.Context(), SessionContext, Session{})
		a.existingHandler.ServeHTTP(w, r.WithContext(sessionContext))
		return
	}
	auth, session := a.connect.isAuthorized(w, r)
	if !auth {
		return
	}
	sessionContext := context.WithValue(r.Context(), SessionContext, session)
	a.existingHandler.ServeHTTP(w, r.WithContext(sessionContext))
}

// NewAuthHandler returns a http.Handler that requires authentication. If the request
// isn't authenticated a 401 Unauthorized is returned to the client, otherwise the
// existing http.Handler is invoked. The Session object is passed along in the request's
// Context.
func (t *GoConnect) NewAuthHandler(existingHandler http.Handler) http.Handler {
	return &authHandler{connect: t, existingHandler: existingHandler}
}
