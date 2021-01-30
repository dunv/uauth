package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// CheckLoginHandler for testing a user's webtoken
var CheckLoginHandler = uhttp.NewHandler(
	uhttp.WithPostModel(AccessTokenRequestModel{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		config, err := uauth.ConfigFromRequest(r)
		if err != nil {
			return err
		}

		req := model.(*AccessTokenRequestModel)

		user, err := uauth.ValidateAccessToken(req.AccessToken, config, r.Context())
		if err != nil {
			return err
		}

		return user
	}),
)
