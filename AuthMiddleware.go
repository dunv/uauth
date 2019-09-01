package uauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

// ContextKey so go does not throw an error
type ContextKey string

// CtxKeyUser is the context key to retrieve user-information from the http-context
const CtxKeyUser = ContextKey("user")

// Auth verify JWT token in request header ("Authorization")
func Auth(bCryptSecret string) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// next.ServeHTTP(w, r)
			token, err := jwt.ParseWithClaims(r.Header.Get("Authorization"), &UserWithClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(bCryptSecret), nil
			})

			if err != nil {
				renderErrorResponse(w)
				return
			}

			if userWithClaims, ok := token.Claims.(*UserWithClaims); ok && token.Valid && userWithClaims.IssuedAt <= int64(time.Now().Unix()) && userWithClaims.ExpiresAt >= int64(time.Now().Unix()) {
				user := userWithClaims.ToUser()
				ctx := context.WithValue(r.Context(), CtxKeyUser, user)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				renderErrorResponse(w)
			}
		}
	}
}

// Error message
type Error struct {
	Error string `json:"error"`
}

func renderErrorResponse(w http.ResponseWriter) {
	js, _ := json.Marshal(Error{"Unauthorized, please make sure you are sending a valid JWT token in the \"Authorization\" header."})
	w.WriteHeader(http.StatusUnauthorized)
	_, err := w.Write(js)
	if err != nil {
		log.Errorf("Error rendering response (%s)", err)
	}
}
