package uauth

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

func AuthHybrid(
	jwtSecrets map[string]string,
	authBasicCredentials map[string]string,
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
					ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", name))
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
					ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", fmt.Sprintf("%sGet", name)))
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// try authbasic
			requestUser, requestPassword, ok := r.BasicAuth()
			requestPasswordMd5 := fmt.Sprintf("%x", md5.Sum([]byte(requestPassword)))
			if ok {
				for allowedUser, allowedPasswordMd5 := range authBasicCredentials {
					if requestUser == allowedUser && requestPasswordMd5 == allowedPasswordMd5 {
						ctx := context.WithValue(r.Context(), CtxKeyCustomUser, allowedUser)
						ctx = context.WithValue(ctx, CtxKeyAuthMethod, "basic")
						ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", "basic"))
						ulog.LogIfError(uhttp.AddLogOutput(w, "user", allowedUser))
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			uhttp.RenderErrorWithStatusCode(w, r, http.StatusUnauthorized, fmt.Errorf("Unauthorized"))
		}
	})
	return &tmp
}
