package uauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
)

// Auth verify JWT token in request header ("Authorization")
func Auth(bCryptSecret string) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user, err := helpers.GetUserFromRequestHeaders(r, bCryptSecret)
			if err != nil {
				uhttp.RenderError(w, r, fmt.Errorf("Unauthorized, please make sure you are sending a valid JWT token in the \"Authorization\" header."))
				return
			}
			ctx := context.WithValue(r.Context(), config.CtxKeyUser, *user)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
