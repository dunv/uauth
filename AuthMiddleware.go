package uauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
)

// ContextKey so go does not throw an error
type ContextKey string

// CtxKeyUser is the context key to retrieve user-information from the http-context
const CtxKeyUser = ContextKey("user")

// Auth verify JWT token in request header ("Authorization")
func Auth(bCryptSecret string) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// bCryptSecret := r.Context().Value(uhttp.CtxKeyBCryptSecret).(string)
			user, err := GetUserFromRequestHeaders(r, bCryptSecret)
			if err != nil {
				uhttp.RenderError(w, r, fmt.Errorf("Unauthorized, please make sure you are sending a valid JWT token in the \"Authorization\" header."))
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyUser, *user)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
