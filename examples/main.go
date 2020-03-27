package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dunv/uauth"
	handlers "github.com/dunv/uauth/handlers"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

func main() {
	ulog.SetLogLevel(ulog.LEVEL_TRACE)

	err := uauth.SetConfig(uauth.Config{
		BCryptSecret:           "randomSecret",
		UserDbConnectionString: "mongodb://localhost:27057",
		UserDbName:             "uauthExample",
		TokenIssuer:            "uauthExample.unverricht.net",
		RefreshTokenValidity:   24 * 7 * time.Hour,
		AccessTokenValidity:    5 * time.Second,
	})

	if err != nil {
		ulog.Fatalf("Could not setup uauth. Exiting (%v)", err)
		return
	}

	// Setup Handlers
	handlers.CreateDefaultHandlers()

	uhttp.Handle("/withAuthorization", uhttp.Handler{
		AddMiddleware: uauth.AuthJWT(),
		GetHandler: func(w http.ResponseWriter, r *http.Request) {
			uhttp.Render(w, r, map[string]string{"auth": "withAuthorization"})
		},
	})

	uhttp.Handle("/noAuthorization", uhttp.Handler{
		GetHandler: func(w http.ResponseWriter, r *http.Request) {
			uhttp.Render(w, r, map[string]string{"auth": "noAuthorization"})
		},
	})

	ip := "0.0.0.0"
	port := 8080
	ulog.Infof("Serving at %s:%d", ip, port)
	ulog.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", ip, port), nil))

}
