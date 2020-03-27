package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var AccessTokenFromRefreshTokenHandler = uhttp.Handler{
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := uauth.ConfigFromRequest(r)
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))

		type refreshTokenRequest struct {
			RefreshToken string `json:"refreshToken"`
		}

		// Parse request
		req := refreshTokenRequest{}
		err := json.NewDecoder(r.Body).Decode(&req)
		defer r.Body.Close()
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Check if token is valid (entails checking the DB)
		userName, err := uauth.ValidateRefreshToken(req.RefreshToken, userService, config, r.Context())
		if err != nil {
			uhttp.RenderWithStatusCode(w, r, http.StatusUnauthorized, uauth.MachineError(uauth.ErrInvalidRefreshToken, err))
			return
		}

		// Get user
		dbUser, err := userService.GetByUserName(userName)
		if err != nil {
			uhttp.RenderWithStatusCode(w, r, http.StatusUnauthorized, uauth.MachineError(uauth.ErrInvalidUser, err))
			return
		}

		// Resolve roles into permissions (currently exact copy of LoginHandler)
		rolesService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
		roleDict, err := rolesService.GetMultipleByName(*dbUser.Roles)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}
		uiUser, err := dbUser.CleanForUI(roleDict)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Create accessToken
		signedAccessToken, err := uauth.GenerateAccessToken(uiUser, userService, config, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		uhttp.Render(w, r, map[string]interface{}{
			"user":         uiUser,
			"accessToken":  signedAccessToken,
			"refreshToken": req.RefreshToken,
		})

	}),
}
