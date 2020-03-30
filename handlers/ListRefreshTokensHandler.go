package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var ListRefreshTokensHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	GetHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		tokens, err := userService.ListRefreshTokens(user.UserName, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, fmt.Errorf("could not find refreshTokens (%s)", err))
			return
		}

		uhttp.Render(w, r, map[string]interface{}{
			"refreshTokens": tokens,
		})
	}),
}
