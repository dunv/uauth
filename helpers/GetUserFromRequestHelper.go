package helpers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dunv/uauth/models"
)

// GetUserFromRequestHeaders tries to get the userModel from a request using the "Authorization" header and "Bearer" scheme
func GetUserFromRequestHeaders(r *http.Request, bCryptSecret string) (*models.User, error) {
	wholeHeader := r.Header.Get("Authorization")
	var parsableToken string
	if strings.Contains(wholeHeader, "Bearer ") {
		parsableToken = strings.Replace(wholeHeader, "Bearer ", "", 1)
	}
	return getUserFromToken(parsableToken, bCryptSecret)
}

// GetUserFromRequest tries to get the userModel from a request using a token attribute from the get params
func GetUserFromRequestGetParams(r *http.Request, bCryptSecret string, queryParam ...*string) (*models.User, error) {
	usedParam := "token"
	if queryParam != nil && len(queryParam) == 1 && queryParam[0] != nil {
		usedParam = *queryParam[0]
	}

	rawParsableToken, ok := r.URL.Query()[usedParam]

	if !ok || len(rawParsableToken[0]) <= 0 {
		return nil, fmt.Errorf("Could not get token from urlParam %s", usedParam)
	}
	parsableToken := rawParsableToken[0]
	return getUserFromToken(parsableToken, bCryptSecret)
}

func getUserFromToken(parsableToken string, bCryptSecret string) (*models.User, error) {
	token, err := jwt.ParseWithClaims(parsableToken, &models.UserWithClaimsRaw{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(bCryptSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("Could not parse token (%s)", err)
	}

	if userWithClaims, ok := token.Claims.(*models.UserWithClaimsRaw); ok && token.Valid && userWithClaims.IssuedAt <= int64(time.Now().Unix()) && userWithClaims.ExpiresAt >= int64(time.Now().Unix()) {
		err = userWithClaims.UnmarshalAdditionalAttributes()
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal additionalAttributes (%s)", err)
		}
		user := userWithClaims.ToUser()
		return &user, nil
	} else {
		return nil, fmt.Errorf("User is using an expired token (%s)", err)
	}
}
