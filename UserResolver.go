package uauth

import (
	"net/http"

	"github.com/dunv/ulog"
)

// Resolves the userName from a request when using JWT
func AuthJWTUserResolver() func(r *http.Request) string {
	return func(r *http.Request) string {
		test := r.Context().Value(CtxKeyUser)
		if test == nil {
			return ""
		}
		if user, ok := test.(User); ok {
			return user.UserName
		}
		ulog.Warnf("wrong type in CtxKeyUser (%T)", test)
		return ""
	}
}

// Resolves the userName from a request when using authBasic
func AuthBasicUserResolver() func(r *http.Request) string {
	return func(r *http.Request) string {
		test := r.Context().Value(CtxKeyUser)
		if test == nil {
			return ""
		}
		user := test.(string)
		return user
	}
}
