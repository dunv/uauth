package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

type loginRequestModel struct {
	User uauth.User `json:"user"`
}

// LoginHandler handler for getting JSON web token
var LoginHandler = uhttp.NewHandler(
	uhttp.WithPostModel(loginRequestModel{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			return err
		}

		// Parse request
		loginRequest := model.(*loginRequestModel)

		// Verify user with password
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		dbUser, err := userService.GetByUserName(loginRequest.User.UserName)
		if err != nil || !(*dbUser).CheckPassword(*loginRequest.User.Password) {
			if err == nil {
				err = fmt.Errorf("nil")
			}
			*returnCode = http.StatusUnauthorized
			return uauth.MachineError(uauth.ErrInvalidUser, fmt.Errorf("No user with this name/password exists (%s)", err))
		}

		// Resolve roles into permissions
		rolesService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
		roleDict, err := rolesService.GetMultipleByName(*dbUser.Roles)
		if err != nil {
			return err
		}
		uiUser, err := dbUser.CleanForUI(roleDict)
		if err != nil {
			return err
		}

		// Create accessToken
		signedAccessToken, err := uauth.GenerateAccessToken(uiUser, config, r.Context())
		if err != nil {
			return err
		}

		// Delete all expired tokens
		err = userService.DeleteExpiredRefreshTokens(dbUser.UserName, r.Context())
		if err != nil {
			return err
		}

		// Create refreshToken
		signedRefreshToken, err := uauth.GenerateRefreshToken(uiUser.UserName, userService, r.Header.Get("User-Agent"), config, r.Context())
		if err != nil {
			return err
		}

		// Render response
		return map[string]interface{}{
			"user":         uiUser,
			"accessToken":  signedAccessToken,
			"refreshToken": signedRefreshToken,
		}
	}),
)
