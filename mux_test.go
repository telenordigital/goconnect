package goconnect

import (
	"fmt"
	"net/http"
)

func ExampleNewAuthHandler() {
	connectid := NewConnectID(NewDefaultConfig(ClientConfig{}))
	// A protected resource - requires authentication
	http.Handle("/extra/", connectid.NewAuthHandler(
		http.StripPrefix("/extra/", http.FileServer(http.Dir("html/extra")))))

	fmt.Println("Hello")
	// Output:
	// Hello
}
