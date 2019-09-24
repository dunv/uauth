package uauth

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
	uhttpHelpers "github.com/dunv/uhttp/helpers"
)

func AuthHybrid(
	jwtSecrets map[string]string,
	authBasicUser string,
	authBasicMd5Password string,
	userModel jwt.Claims,
) *uhttp.Middleware {
	tmp := uhttp.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// try all secrets in Headers
			for name, secret := range jwtSecrets {
				user, err := helpers.GetCustomUserFromRequestHeaders(r, secret, userModel)
				if err == nil {
					ctx := context.WithValue(r.Context(), CtxKeyCustomUser, user)
					ctx = context.WithValue(ctx, CtxKeyAuthMethod, name)
					ctx = uhttpHelpers.AddToLogLine(ctx, "authMethod", name)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// try all secrets in getparam
			for name, secret := range jwtSecrets {
				user, err := helpers.GetCustomUserFromRequestGetParams(r, secret, userModel)
				if err == nil {
					ctx := context.WithValue(r.Context(), CtxKeyCustomUser, user)
					ctx = context.WithValue(ctx, CtxKeyAuthMethod, fmt.Sprintf("%sGet", name))
					ctx = uhttpHelpers.AddToLogLine(ctx, "authMethod", fmt.Sprintf("%sGet", name))
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// try authbasic
			user, pass, ok := r.BasicAuth()
			passMd5 := fmt.Sprintf("%x", md5.Sum([]byte(pass)))
			if !ok || user != authBasicUser || passMd5 != authBasicMd5Password {
				uhttp.RenderErrorWithStatusCode(w, r, http.StatusUnauthorized, fmt.Errorf("Unauthorized"))
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyCustomUser, user)
			ctx = context.WithValue(ctx, CtxKeyAuthMethod, "basic")
			ctx = uhttpHelpers.AddToLogLine(ctx, "authMethod", "basic")
			ctx = uhttpHelpers.AddToLogLine(ctx, "user", authBasicUser)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
	return &tmp
}
