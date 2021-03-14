package main

import (
	"net/http"
	"time"

	"github.com/dunv/uauth"
	handlers "github.com/dunv/uauth/handlers"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

type additional struct {
	UserAttr1 int      `bson:"userAttr1" json:"userAttr1"`
	UserAttr2 []string `bson:"userAttr2" json:"userAttr2"`
}

func main() {
	ulog.SetLogLevel(ulog.LEVEL_TRACE)

	u := uhttp.NewUHTTP()

	if err := uauth.SetConfig(uauth.Config{
		UHTTP:                  u,
		BCryptSecret:           "randomSecret",
		UserDbConnectionString: "mongodb://localhost:27057",
		UserDbName:             "uauthExample",
		TokenIssuer:            "uauthExample.unverricht.net",
		RefreshTokenValidity:   24 * 7 * time.Hour,
		AccessTokenValidity:    24 * time.Hour,
	}); err != nil {
		ulog.Fatalf("Could not setup uauth. Exiting (%v)", err)
	}

	// Setup Handlers
	handlers.CreateDefaultHandlers(u)

	u.Handle("/withAuthorization", uhttp.NewHandler(
		uhttp.WithMiddlewares(uauth.AuthJWT()),
		uhttp.WithGet(func(r *http.Request, ret *int) interface{} {
			additionalAttrs := additional{}
			_, err := uauth.UserFromRequest(r, &additionalAttrs)
			if err != nil {
				return err
			}
			return map[string]interface{}{"auth": "withAuthorization", "additionalAttrs": additionalAttrs}
		}),
	))

	u.Handle("/noAuthorization", uhttp.NewHandler(
		uhttp.WithGet(func(r *http.Request, ret *int) interface{} {
			return map[string]string{"auth": "noAuthorization"}
		}),
	))
	ulog.Fatal(u.ListenAndServe())
}
