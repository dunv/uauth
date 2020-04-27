package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// Trade in an old refresh-token for a new one
var RenewRefreshTokenHandler = uhttp.Handler{
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
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
			uhttp.RenderError(w, r, err)
			return
		}

		// Check if token is valid (entails checking the DB)
		refreshTokenModel, err := uauth.ValidateRefreshToken(req.RefreshToken, userService, config, r.Context())
		if err != nil {
			uhttp.RenderWithStatusCode(w, r, http.StatusUnauthorized, uauth.MachineError(uauth.ErrInvalidRefreshToken, err))
			return
		}

		// Remove the token from the DB
		err = userService.RemoveRefreshToken(refreshTokenModel.UserName, req.RefreshToken, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Create a new one and return it
		newRefreshToken, err := uauth.GenerateRefreshToken(refreshTokenModel.UserName, userService, refreshTokenModel.Device, config, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		uhttp.Render(w, r, map[string]interface{}{
			"refreshToken": newRefreshToken,
		})

	}),
}
