package helpers

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

func GetCustomUserFromRequestHeaders(r *http.Request, bCryptSecret string, userModel jwt.Claims) (interface{}, error) {
	wholeHeader := r.Header.Get("Authorization")
	var parsableToken string
	if strings.Contains(wholeHeader, "Bearer ") {
		parsableToken = strings.Replace(wholeHeader, "Bearer ", "", 1)
	}

	return getCustomUserFromToken(parsableToken, bCryptSecret, userModel)
}

func GetCustomUserFromRequestGetParams(r *http.Request, bCryptSecret string, userModel jwt.Claims, queryParam ...*string) (interface{}, error) {
	usedParam := "jwt"
	if queryParam != nil && len(queryParam) == 1 && queryParam[0] != nil {
		usedParam = *queryParam[0]
	}

	rawParsableToken, ok := r.URL.Query()[usedParam]

	if !ok || len(rawParsableToken[0]) <= 0 {
		return nil, fmt.Errorf("Could not get token from urlParam %s", usedParam)
	}
	parsableToken := rawParsableToken[0]
	return getCustomUserFromToken(parsableToken, bCryptSecret, userModel)
}

func getCustomUserFromToken(parsableToken string, bCryptSecret string, userModel jwt.Claims) (interface{}, error) {
	reflectModel := reflect.New(reflect.TypeOf(userModel)).Interface()
	token, err := jwt.ParseWithClaims(parsableToken, reflectModel.(jwt.Claims), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(bCryptSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("Could not parse token (%s)", err)
	}

	if err = token.Claims.Valid(); err == nil && token.Valid {
		return token.Claims, nil
	} else {
		return nil, fmt.Errorf("User is using an invalid token (%s)", err)
	}
}
