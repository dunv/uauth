package uauth

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthBasic <-
func AuthBasic(wantedUsername string, wantedMd5Password string) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			user, pass, ok := r.BasicAuth()
			passMd5 := fmt.Sprintf("%x", md5.Sum([]byte(pass)))

			if !ok || user != wantedUsername || passMd5 != wantedMd5Password {
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
