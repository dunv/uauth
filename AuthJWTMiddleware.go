package uauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
	uhttpHelpers "github.com/dunv/uhttp/helpers"
	uhttpModels "github.com/dunv/uhttp/models"
)

// Auth verify JWT token in request header ("Authorization")
var authJWTMiddleware = uhttpModels.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := helpers.GetUserFromRequestHeaders(r, BCryptSecret(r))
		if err != nil {
			uhttp.RenderError(w, r, fmt.Errorf("Unauthorized"))
			return
		}
		ctx := context.WithValue(r.Context(), CtxKeyUser, *user)
		ctx = context.WithValue(ctx, CtxKeyAuthMethod, "jwt")
		ctx = uhttpHelpers.AddToLogLine(ctx, "authMethod", "jwt")
		ctx = uhttpHelpers.AddToLogLine(ctx, "user", user.UserName)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
})

func AuthJWT() *uhttpModels.Middleware {
	return &authJWTMiddleware
}
