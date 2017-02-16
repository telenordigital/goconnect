package goconnect

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
