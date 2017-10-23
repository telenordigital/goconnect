/*Package goconnect is an authentication library for the Telenor CONNECT ID service.

The go-connectid library is an easy-to-use library when you want to integrate
with the Telenor CONNECT ID service. It can be retrofitted to any http service
that uses the http package with a few simple changes in the service setup.

Creating a new client

Start by creating a new client configuration and Connect client:

    config := connect.NewDefaultConfig(ClientConfig{
        Host:                      connect.StagingHost,
        ClientID:                  username,
        Password:                  password,
        LoginCompleteRedirectURI:  "/main.html",
        LogoutCompleteRedirectURI: "/",
    })

    connectid := connect.NewConnectID(config)


Setting up the HTTP mux

Once the client is created you can wrap the http.Handler and http.HandlerFunc
elements in your server:

    // This the default start page. It uses the unwrapped handler since it
    // won't require authentication
    http.HandleFunc("/", startPageHandler)

    // This page will require authentication
    http.HandleFunc("/main.html", connectid.NewAuthHandlerFunc(mainPageHandler))

    // Protected resources requires authentication
    http.Handle("/extra/", connectid.NewAuthHandler(
        http.StripPrefix("/extra/", http.FileServer(http.Dir("html/extra")))))

    // API endpoint - requires authentication
    http.HandleFunc("/api/oneliner", connectid.NewAuthHandlerFunc(api.OneLinerHandlerFunc))

The session object is stored into the http.Request context. Retrieve the context
with the SessionContext key:

    // Write the logged in user's name
    func myHandlerFunc(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Header().Set("Content-Type", "text/plain")

        session := r.Context().Value(connect.SessionContext)
        w.Write([]byte("Hello, ", session.Name))
    }

The callbacks for the OAuth service must be set up according to your configuration.

The default development client is set up to redirect to http://localhost:8080/connect/complete
and http://localhost:8080/connect/login and the Go-Connect handler is set up
the following way:

  http.Handle("/connect/", connectid.Handler())




*/
package goconnect
