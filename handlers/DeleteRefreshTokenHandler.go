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

var DeleteRefreshTokenHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares([]uhttp.Middleware{uauth.AuthJWT()}),
	uhttp.WithPostModel(deleteRefreshTokenRequest{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			return err
		}
		tokenModel := model.(*deleteRefreshTokenRequest)

		err = userService.RemoveRefreshToken(user.UserName, tokenModel.RefreshToken, r.Context())
		if err != nil {
			return fmt.Errorf("could not delete refreshToken (%s)", err)
		}
		*returnCode = http.StatusNoContent
		return nil
	}),
)
