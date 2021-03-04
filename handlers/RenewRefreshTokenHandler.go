package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// Trade in an old refresh-token for a new one
var RenewRefreshTokenHandler = uhttp.NewHandler(
	uhttp.WithPostModel(RefreshTokenRequestModel{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			return err
		}

		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))

		// Parse request
		req := model.(*RefreshTokenRequestModel)

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

		// Delete all expired tokens ("request-based-cron")
		err = userService.DeleteExpiredRefreshTokens(refreshTokenModel.UserName, r.Context())
		if err != nil {
			return err
		}

		// Create a new one
		signedRefreshToken, err := uauth.GenerateRefreshToken(refreshTokenModel.UserName, userService, refreshTokenModel.Device, config, r.Context())
		if err != nil {
			return err
		}

		// Generate an accessToken as well (to simplify the client API)
		uiUser, err := userService.GetUiUserByUserName(refreshTokenModel.UserName)
		if err != nil {
			return err
		}
		signedAccessToken, err := uauth.GenerateAccessToken(uiUser, config, r.Context())
		if err != nil {
			return err
		}

		return TokenResponseModel{
			User:         uiUser,
			AccessToken:  signedAccessToken,
			RefreshToken: signedRefreshToken,
		}
	}),
)
