package uauth

import (
	"net/http"

	"github.com/dunv/uauth/models"
	"github.com/dunv/ulog"
)

func AuthJWTUserResolver() func(r *http.Request) string {
	return func(r *http.Request) string {
		test := r.Context().Value(CtxKeyUser)
		if test == nil {
			return ""
		}
		if user, ok := test.(models.User); ok {
			return user.UserName
		}
		ulog.Warnf("wrong type in CtxKeyUser (%T)", test)
		return ""
	}
}

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
