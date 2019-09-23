package uauth

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	uhttpHelpers "github.com/dunv/uhttp/helpers"
)

func AuthBasic(wantedUsername string, wantedMd5Password string) *uhttp.Middleware {
	tmp := uhttp.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			user, pass, ok := r.BasicAuth()
			passMd5 := fmt.Sprintf("%x", md5.Sum([]byte(pass)))

			if !ok || user != wantedUsername || passMd5 != wantedMd5Password {
				uhttp.RenderErrorWithStatusCode(w, r, http.StatusUnauthorized, fmt.Errorf("Unauthorized"))
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyUser, user)
			ctx = context.WithValue(ctx, CtxKeyAuthMethod, "basic")
			ctx = uhttpHelpers.AddToLogLine(ctx, "authMethod", "basic")
			ctx = uhttpHelpers.AddToLogLine(ctx, "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
	return &tmp
}
