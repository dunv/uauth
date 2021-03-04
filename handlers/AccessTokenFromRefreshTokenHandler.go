package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var AccessTokenFromRefreshTokenHandler = uhttp.NewHandler(
	uhttp.WithPostModel(RefreshTokenRequestModel{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			return err
		}

		// Parse request
		req := model.(*RefreshTokenRequestModel)

		// Check if token is valid (entails checking the DB)
		refreshTokenModel, err := uauth.ValidateRefreshToken(req.RefreshToken, userService, config, r.Context())
		if err != nil {
			*returnCode = http.StatusUnauthorized
			return uauth.MachineError(uauth.ErrInvalidRefreshToken, err)
		}

		// Get user
		uiUser, err := userService.GetUiUserByUserName(refreshTokenModel.UserName)
		if err != nil {
			*returnCode = http.StatusUnauthorized
			return uauth.MachineError(uauth.ErrInvalidUser, err)
		}

		// Create accessToken
		signedAccessToken, err := uauth.GenerateAccessToken(uiUser, config, r.Context())
		if err != nil {
			return err
		}

		return TokenResponseModel{
			User:         uiUser,
			AccessToken:  signedAccessToken,
			RefreshToken: req.RefreshToken,
		}
	}),
)
