package helpers 

import (
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
)

func UserResolver(r *http.Request) string {
	test := r.Context().Value(config.CtxKeyUser)
	if test == nil {
		return ""
	}
	user := test.(models.User)
	return user.UserName
}

func AuthBasicUserResolver(r *http.Request) string {
	test := r.Context().Value(config.CtxKeyUser)
	if test == nil {
		return ""
	}
	user := test.(string)
	return user
}
