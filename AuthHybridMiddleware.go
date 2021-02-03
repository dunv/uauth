package uauth

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dunv/uhttp"
)

func AuthHybrid(
	jwtSecrets map[string]string,
	authBasicCredentials map[string]string,
	userModel jwt.Claims,
) uhttp.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// try all secrets in Headers
			for name, secret := range jwtSecrets {
				user, err := GetCustomUserFromRequestHeaders(r, secret, userModel)
				if err == nil {
					ctx := context.WithValue(r.Context(), CtxKeyUser, user)
					ctx = context.WithValue(ctx, CtxKeyAuthMethod, name)
					_ = uhttp.AddLogOutput(w, "authMethod", name) // if we are using websockets this returns an error which we want to ignore (no logging responseWriter available)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// try all secrets in getparam
			for name, secret := range jwtSecrets {
				user, err := GetCustomUserFromRequestGetParams(r, secret, userModel)
				if err == nil {
					ctx := context.WithValue(r.Context(), CtxKeyUser, user)
					ctx = context.WithValue(ctx, CtxKeyAuthMethod, fmt.Sprintf("%sGet", name))
					_ = uhttp.AddLogOutput(w, "authMethod", fmt.Sprintf("%sGet", name)) // if we are using websockets this returns an error which we want to ignore
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
						ctx := context.WithValue(r.Context(), CtxKeyUser, allowedUser)
						ctx = context.WithValue(ctx, CtxKeyAuthMethod, "basic")
						_ = uhttp.AddLogOutput(w, "authMethod", "basic") // if we are using websockets this returns an error which we want to ignore
						_ = uhttp.AddLogOutput(w, "user", allowedUser)   // if we are using websockets this returns an error which we want to ignore
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			packageConfig.UHTTP.RenderErrorWithStatusCode(w, r, http.StatusUnauthorized, fmt.Errorf("Unauthorized"), false)
		}
	}
}
