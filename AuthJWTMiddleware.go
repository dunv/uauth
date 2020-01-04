package uauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

// Auth verify JWT token in request header ("Authorization")
// This method assumes the BCryptSecret already attached to the request context
// i.e. uauth must have been initialized with uauth.SetConfig(...)
func AuthJWT() *uhttp.Middleware {
	tmp := uhttp.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if packageConfig.UserDbName == "" || packageConfig.UserDbClient == nil || packageConfig.BCryptSecret == "" {
				ulog.Panic("uauth packageConfig has not been set, unable to use AuthJWT()", packageConfig)
			}

			user, err := helpers.GetUserFromRequestHeaders(r, BCryptSecret(r))
			if err != nil {
				ulog.Infof("Denying access (%s)", err)
				uhttp.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyUser, *user)
			ctx = context.WithValue(ctx, CtxKeyAuthMethod, "jwt")
			ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", "jwt"))
			ulog.LogIfError(uhttp.AddLogOutput(w, "user", user.UserName))
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
	return &tmp
}
