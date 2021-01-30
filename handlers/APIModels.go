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
type LoginRequestModel struct {
	User     *uauth.User `json:"user,omitempty"`
	UserName *string     `json:"userName,omitempty"`
	Password *string     `json:"password,omitempty"`
}

func (l *LoginRequestModel) GetUserName() string {
	if l.UserName != nil {
		return *l.UserName
	}
	if l.User != nil {
		return l.User.UserName
	}
	return ""
}

func (l *LoginRequestModel) GetPassword() string {
	if l.Password != nil {
		return *l.Password
	}
	if l.User != nil {
		return *l.User.Password
	}
	return ""
}
