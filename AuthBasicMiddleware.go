package uauth

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uhttp"
)

func AuthBasic(wantedUsername string, wantedMd5Password string) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			user, pass, ok := r.BasicAuth()
			passMd5 := fmt.Sprintf("%x", md5.Sum([]byte(pass)))

			if !ok || user != wantedUsername || passMd5 != wantedMd5Password {
				uhttp.RenderErrorWithStatusCode(w, r, http.StatusUnauthorized, fmt.Errorf("Unauthorized"))
				return
			}

			ctx := context.WithValue(r.Context(), config.CtxKeyUser, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
