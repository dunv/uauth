package uauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// AuthBasic <-
func AuthBasic(username string, password string) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			user, pass, ok := r.BasicAuth()

			if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
				js, _ := json.Marshal(map[string]string{
					"error": "unauthorized",
				})
				w.Header().Add("Content-Type", "application/json")
				w.WriteHeader(401)
				w.Write(js)
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyUser, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
