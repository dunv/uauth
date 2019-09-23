package uauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
	uhttpHelpers "github.com/dunv/uhttp/helpers"
)

// Auth verify JWT token in url ("jwt=...")
// This method assumes the BCryptSecret already attached to the request context
// i.e. uauth must have been initialized with uauth.SetConfig(...)
func AuthJWTGet() *uhttp.Middleware {
	tmp := uhttp.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user, err := helpers.GetUserFromRequestGetParams(r, BCryptSecret(r))
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
	return &tmp
}
