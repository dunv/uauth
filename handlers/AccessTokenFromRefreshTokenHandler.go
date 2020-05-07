package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var AccessTokenFromRefreshTokenHandler = uhttp.NewHandler(
	uhttp.WithPost(func(r *http.Request, returnCode *int) interface{} {

		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			return err
		}

		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))

		type refreshTokenRequest struct {
			RefreshToken string `json:"refreshToken"`
		}

		// Parse request
		req := refreshTokenRequest{}
		err = json.NewDecoder(r.Body).Decode(&req)
		defer r.Body.Close()
		if err != nil {
			return err
		}

		// Check if token is valid (entails checking the DB)
		refreshTokenModel, err := uauth.ValidateRefreshToken(req.RefreshToken, userService, config, r.Context())
		if err != nil {
			*returnCode = http.StatusUnauthorized
			return uauth.MachineError(uauth.ErrInvalidRefreshToken, err)
		}

		// Get user
		dbUser, err := userService.GetByUserName(refreshTokenModel.UserName)
		if err != nil {
			*returnCode = http.StatusUnauthorized
			return uauth.MachineError(uauth.ErrInvalidUser, err)
		}

		// Resolve roles into permissions (currently exact copy of LoginHandler)
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

		return map[string]interface{}{
			"user":         uiUser,
			"accessToken":  signedAccessToken,
			"refreshToken": req.RefreshToken,
		}
	}),
)
