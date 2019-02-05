package uauth

import (
	"net/http"
)

// UserResolver <-
func UserResolver(r *http.Request) string {
	test := r.Context().Value(CtxKeyUser)
	if test == nil {
		return ""
	}
	user := test.(User)
	return user.UserName
}

// AuthBasicUserResolver <-
func AuthBasicUserResolver(r *http.Request) string {
	test := r.Context().Value(CtxKeyUser)
	if test == nil {
		return ""
	}
	user := test.(string)
	return user
}
