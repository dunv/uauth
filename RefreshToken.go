package uauth

import (
	"context"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type RefreshTokenModel struct {
	Claims   jwt.MapClaims `json:"claims"` // jwt.MapClaims comes with default validation
	UserName string        `json:"userName"`
	Device   string        `json:"device"`
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

func GenerateRefreshToken(
	userName string,
	userService *UserService,
	device string,
	config *Config,
	ctx context.Context,
) (string, error) {
	rtClaims := RefreshTokenModel{
		Claims: jwt.MapClaims{
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(config.RefreshTokenValidity).Unix(),
			"iss": config.TokenIssuer,
		},
		UserName: userName,
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.BCryptSecret))
	if err != nil {
		return "", err
	}
	err = userService.AddRefreshToken(userName, signedRefreshToken, ctx)
	if err != nil {
		return "", err
	}
	return signedRefreshToken, nil
}

// Validates the following
// - parse token
// - verify signature
// - verify validity
// - check if token is in Database and assigned to the user encoded in the token
func ValidateRefreshToken(refreshToken string, userService *UserService, config *Config, ctx context.Context) (*RefreshTokenModel, error) {
	// First parse content
	refreshTokenModel, _, err := ParseRefreshToken(refreshToken, config)
	if err != nil {
		return nil, err
	}

	// Check if token is in DB
	err = userService.FindRefreshToken(refreshTokenModel.UserName, refreshToken, ctx)
	if err != nil {
		return nil, fmt.Errorf("could not validate refreshToken (%s)", err)
	}
	return refreshTokenModel, nil
}

// Parses a refreshToken into RefreshTokenModel
func ParseRefreshToken(refreshToken string, config *Config) (*RefreshTokenModel, *jwt.Token, error) {
	refreshTokenModel := RefreshTokenModel{}
	token, err := jwt.ParseWithClaims(refreshToken, &refreshTokenModel, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.BCryptSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, nil, err
	}
	return &refreshTokenModel, token, nil
}
