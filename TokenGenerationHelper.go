package uauth

import (
	"context"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type AccessTokenModel struct {
	jwt.MapClaims `json:"claims"` // jwt.MapClaims comes with default validation
	User          *User           `json:"user"`
}

type RefreshTokenModel struct {
	jwt.MapClaims `json:"claims"` // jwt.MapClaims comes with default validation
	UserName      string          `json:"userName"`
}

const (
	TOKEN_USER_ATTR string = "user"
)

func GenerateRefreshToken(userName string, userService *UserService, config Config, ctx context.Context) (string, error) {
	rtClaims := RefreshTokenModel{
		MapClaims: jwt.MapClaims{
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(config.RefreshTokenValidity).Unix(),
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
func ValidateRefreshToken(refreshToken string, userService *UserService, config Config, ctx context.Context) (string, error) {
	// First validate content
	refreshTokenModel := RefreshTokenModel{}
	token, err := jwt.ParseWithClaims(refreshToken, &refreshTokenModel, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.BCryptSecret), nil
	})
	if err != nil || !token.Valid {
		return "", err
	}

	// Check if token is in DB
	err = userService.FindRefreshToken(refreshTokenModel.UserName, refreshToken, ctx)
	if err != nil {
		return "", fmt.Errorf("could not validate refreshToken (%s)", err)
	}
	return refreshTokenModel.UserName, nil
}

func GenerateAccessToken(
	user *User,
	userService *UserService,
	config Config,
	ctx context.Context,
) (string, error) {
	atClaims := AccessTokenModel{
		MapClaims: jwt.MapClaims{
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(config.AccessTokenValidity).Unix(),
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
	config Config,
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
