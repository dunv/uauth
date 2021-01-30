package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// LoginHandler handler for getting JSON web token
var LoginHandler = uhttp.NewHandler(
	uhttp.WithPostModel(LoginRequestModel{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			return err
		}

		// Parse request
		loginRequest := model.(*LoginRequestModel)

		// Verify user with password
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		uiUser, err := userService.GetUIUserByUserNameAndCheckPassword(loginRequest.GetUserName(), loginRequest.GetPassword())
		if err != nil {
			*returnCode = http.StatusUnauthorized
			return uauth.MachineError(uauth.ErrInvalidUser, fmt.Errorf("No user with this name/password exists (%s)", err))
		}

		// Create accessToken
		signedAccessToken, err := uauth.GenerateAccessToken(uiUser, config, r.Context())
		if err != nil {
			return err
		}

		// Delete all expired tokens ("request-based-cron")
		err = userService.DeleteExpiredRefreshTokens(uiUser.UserName, r.Context())
		if err != nil {
			return err
		}

		// Create refreshToken
		signedRefreshToken, err := uauth.GenerateRefreshToken(uiUser.UserName, userService, r.Header.Get("User-Agent"), config, r.Context())
		if err != nil {
			return err
		}

		// Render response
		return TokenResponseModel{
			User:         uiUser,
			AccessToken:  signedAccessToken,
			RefreshToken: signedRefreshToken,
		}
	}),
)
