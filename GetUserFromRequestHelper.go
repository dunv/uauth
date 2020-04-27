package uauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// GetUserFromRequestHeaders tries to get the userModel from a request using the "Authorization" header and "Bearer" scheme
func GetUserFromRequestHeaders(r *http.Request) (*User, error) {
	config, err := ConfigFromRequest(r)
	if err != nil {
		return nil, err
	}

	wholeHeader := r.Header.Get("Authorization")
	var parsableToken string
	if strings.Contains(wholeHeader, "Bearer ") {
		parsableToken = strings.Replace(wholeHeader, "Bearer ", "", 1)
	}

	return getUserFromToken(parsableToken, config, r.Context())
}

// GetUserFromRequest tries to get the userModel from a request using a token attribute from the get params
func GetUserFromRequestGetParams(r *http.Request, queryParam ...*string) (*User, error) {
	config, err := ConfigFromRequest(r)
	if err != nil {
		return nil, err
	}

	usedParam := "jwt"
	if len(queryParam) == 1 && queryParam[0] != nil {
		usedParam = *queryParam[0]
	}

	rawParsableToken, ok := r.URL.Query()[usedParam]

	if !ok || len(rawParsableToken[0]) <= 0 {
		return nil, fmt.Errorf("Could not get token from urlParam %s", usedParam)
	}
	parsableToken := rawParsableToken[0]
	return getUserFromToken(parsableToken, config, r.Context())
}

func getUserFromToken(parsableToken string, config *Config, ctx context.Context) (*User, error) {
	return ValidateAccessToken(parsableToken, config, ctx)
}
