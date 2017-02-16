package goconnect

import "fmt"

func ExampleNewDefaultConfig() {
	config := NewDefaultConfig(ClientConfig{
		Host:                   StagingHost,
		ClientID:               "client-id",
		Password:               "client-secret",
		LoginCompleteRedirect:  "/main.html",
		LogoutCompleteRedirect: "/",
	})

	fmt.Println(config.LoginCompleteRedirect)
	fmt.Println(config.LogoutCompleteRedirect)
	// Output:
	// /main.html
	// /
}
