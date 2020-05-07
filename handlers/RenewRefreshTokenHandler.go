package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

type refreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// Trade in an old refresh-token for a new one
var RenewRefreshTokenHandler = uhttp.NewHandler(
	uhttp.WithPostModel(refreshTokenRequest{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			return err
		}

		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))

		// Parse request
		req := model.(*refreshTokenRequest)

		// Check if token is valid (entails checking the DB)
		refreshTokenModel, err := uauth.ValidateRefreshToken(req.RefreshToken, userService, config, r.Context())
		if err != nil {
			*returnCode = http.StatusUnauthorized
			return uauth.MachineError(uauth.ErrInvalidRefreshToken, err)
		}

		// Remove the token from the DB
		err = userService.RemoveRefreshToken(refreshTokenModel.UserName, req.RefreshToken, r.Context())
		if err != nil {
			return err
		}

		// Create a new one and return it
		newRefreshToken, err := uauth.GenerateRefreshToken(refreshTokenModel.UserName, userService, refreshTokenModel.Device, config, r.Context())
		if err != nil {
			return err
		}

		return map[string]interface{}{
			"refreshToken": newRefreshToken,
		}
	}),
)
