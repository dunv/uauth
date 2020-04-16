package uauth

import (
	"github.com/dgrijalva/jwt-go"
)

type AccessTokenModel struct {
	Claims jwt.MapClaims `json:"claims"` // jwt.MapClaims comes with default validation
	User   *User         `json:"user"`
}

func (t AccessTokenModel) Valid() error {
	err := t.Claims.Valid()
	if err != nil {
		return err
	}

	var vErr error
	if !t.Claims.VerifyIssuer(packageConfig.TokenIssuer, true) {
		vErr = jwt.NewValidationError("Token has wrong issuer", 1<<0)
	}
	return vErr
}

type RefreshTokenModel struct {
	Claims   jwt.MapClaims `json:"claims"` // jwt.MapClaims comes with default validation
	UserName string        `json:"userName"`
}

func (t RefreshTokenModel) Valid() error {
	err := t.Claims.Valid()
	if err != nil {
		return err
	}

	var vErr error
	if !t.Claims.VerifyIssuer(packageConfig.TokenIssuer, true) {
		vErr = jwt.NewValidationError("Token has wrong issuer", 1<<0)
	}
	return vErr
}
