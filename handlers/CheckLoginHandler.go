package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// CheckLoginHandler for testing a user's webtoken
var CheckLoginHandler = uhttp.Handler{
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := uauth.ConfigFromRequest(r)
		// Parse request
		type checkLoginRequest struct {
			AccessToken string `json:"accessToken"`
		}
		req := checkLoginRequest{}
		err := json.NewDecoder(r.Body).Decode(&req)
		defer r.Body.Close()
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		user, err := uauth.ValidateAccessToken(req.AccessToken, config, r.Context())
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		uhttp.Render(w, r, user)
	}),
}
