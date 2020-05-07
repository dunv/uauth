package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// CheckLoginHandler for testing a user's webtoken
var CheckLoginHandler = uhttp.NewHandler(uhttp.WithPost(func(r *http.Request, returnCode *int) interface{} {
	config, err := uauth.ConfigFromRequest(r)
	if err != nil {
		return err
	}

	// Parse request
	type checkLoginRequest struct {
		AccessToken string `json:"accessToken"`
	}
	req := checkLoginRequest{}
	err = json.NewDecoder(r.Body).Decode(&req)
	defer r.Body.Close()
	if err != nil {
		return err
	}

	user, err := uauth.ValidateAccessToken(req.AccessToken, config, r.Context())
	if err != nil {
		return err
	}

	return user
}))
