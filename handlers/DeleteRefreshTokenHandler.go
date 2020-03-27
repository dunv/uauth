package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

type deleteRefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

var DeleteRefreshTokenHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	PostModel:     deleteRefreshTokenRequest{},
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		user := uauth.UserFromRequest(r)
		tokenModel := uhttp.ParsedModel(r).(*deleteRefreshTokenRequest)

		err := userService.RemoveRefreshToken(user.UserName, tokenModel.RefreshToken, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, fmt.Errorf("could not delete refreshToken (%s)", err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}),
}
