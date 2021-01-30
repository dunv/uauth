package handlers

import "github.com/dunv/uauth"

type RefreshTokenRequestModel struct {
	RefreshToken string `json:"refreshToken"`
}

type AccessTokenRequestModel struct {
	AccessToken string `json:"accessToken"`
}

type TokenResponseModel struct {
	User         *uauth.User `json:"user"`
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
}
