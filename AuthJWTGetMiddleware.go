package uauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhelpers"
	"github.com/dunv/uhttp"
	uhttpHelpers "github.com/dunv/uhttp/helpers"
	uhttpModels "github.com/dunv/uhttp/models"
)

// Auth verify JWT token in url ("jwt=...")
var authJWTGetMiddleware = uhttpModels.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := helpers.GetUserFromRequestGetParams(r, BCryptSecret(r), uhelpers.PtrToString("jwt"))
		if err != nil {
			uhttp.RenderError(w, r, fmt.Errorf("Unauthorized"))
			return
		}
		ctx := context.WithValue(r.Context(), CtxKeyUser, *user)
		ctx = context.WithValue(ctx, CtxKeyAuthMethod, "jwtGet")
		ctx = uhttpHelpers.AddToLogLine(ctx, "authMethod", "jwtGet")
		ctx = uhttpHelpers.AddToLogLine(ctx, "user", user.UserName)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
})

func AuthJWTGet() *uhttpModels.Middleware {
	return &authJWTGetMiddleware
}
