package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// LoginHandler handler for getting JSON web token
var LoginHandler = uhttp.Handler{
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Parse request
		type loginRequestModel struct {
			User uauth.User `json:"user"`
		}
		loginRequest := loginRequestModel{}
		err = json.NewDecoder(r.Body).Decode(&loginRequest)
		defer r.Body.Close()
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Verify user with password
		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		dbUser, err := userService.GetByUserName(loginRequest.User.UserName)
		if err != nil || !(*dbUser).CheckPassword(*loginRequest.User.Password) {
			if err == nil {
				err = fmt.Errorf("nil")
			}
			uhttp.RenderWithStatusCode(w, r, http.StatusUnauthorized, uauth.MachineError(uauth.ErrInvalidUser, fmt.Errorf("No user with this name/password exists (%s)", err)))
			return
		}

		// Resolve roles into permissions
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
		signedAccessToken, err := uauth.GenerateAccessToken(uiUser, config, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Delete all expired tokens
		err = userService.DeleteExpiredRefreshTokens(dbUser.UserName, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Create refreshToken
		signedRefreshToken, err := uauth.GenerateRefreshToken(uiUser.UserName, userService, r.Header.Get("User-Agent"), config, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Render response
		uhttp.Render(w, r, map[string]interface{}{
			"user":         uiUser,
			"accessToken":  signedAccessToken,
			"refreshToken": signedRefreshToken,
		})
	}),
}
