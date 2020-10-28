package uauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

// Auth verify JWT token in url ("jwt=...")
// This method assumes the BCryptSecret already attached to the request context
// i.e. uauth must have been initialized with uauth.SetConfig(...)
func AuthJWTGet() uhttp.Middleware {
	if packageConfig.UserDbName == "" || packageConfig.UserDbConnectionString == "" || packageConfig.BCryptSecret == "" {
		ulog.Errorf("uauth packageConfig has not been set, unable to use AuthJWTGet() (%v)", packageConfig)
		return nil
	}
	tmp := uhttp.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user, err := GetUserFromRequestGetParams(r)
			if err != nil {
				ulog.Infof("Denying access (%s)", err)
				packageConfig.UHTTP.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyUser, *user)
			ctx = context.WithValue(ctx, CtxKeyAuthMethod, "jwtGet")
			ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", "jwtGet"))
			ulog.LogIfError(uhttp.AddLogOutput(w, "user", user.UserName))
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
	return tmp
}
