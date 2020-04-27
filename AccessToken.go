package uauth

import (
	"context"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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

func GenerateAccessToken(
	user *User,
	config *Config,
	ctx context.Context,
) (string, error) {
	atClaims := AccessTokenModel{
		Claims: jwt.MapClaims{
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(config.AccessTokenValidity).Unix(),
			"iss": config.TokenIssuer,
		},
		User: user,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(config.BCryptSecret))
	if err != nil {
		return "", err
	}
	return signedAccessToken, nil
}

// Validates the following
// - parse token
// - verify signature
// - verify validity
func ValidateAccessToken(
	accessToken string,
	config *Config,
	ctx context.Context,
) (*User, error) {
	accessTokenModel := AccessTokenModel{}
	token, err := jwt.ParseWithClaims(accessToken, &accessTokenModel, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.BCryptSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}

	return accessTokenModel.User, nil
}
