package uauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dunv/uhttp"
)

type checkLoginRequest struct {
	Token string `json:"token"`
}

type checkLoginResponse struct {
	User                       User `json:"user"`
	SignatureValid             bool `json:"signatureValid"`
	ContainsRequiredAttributes bool `json:"containsRequiredAttributes"`
	IssuedBeforeNow            bool `json:"issuedBeforeNow,omitempty"`
	ExpiryAfterNow             bool `json:"expiryAfterNow,omitempty"`
	Valid                      bool `json:"valid,omitempty"`
}

func (r checkLoginResponse) AllOk() bool {
	return r.SignatureValid && r.ContainsRequiredAttributes && r.IssuedBeforeNow && r.ExpiryAfterNow
}

var checkLoginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Parse request
	checkLoginRequest := checkLoginRequest{}
	err := json.NewDecoder(r.Body).Decode(&checkLoginRequest)
	defer r.Body.Close()
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	checkLoginResponse := checkLoginResponse{}

	// Parse token and check signature
	bCryptSecret := r.Context().Value(uhttp.CtxKeyBCryptSecret).(string)
	token, err := jwt.ParseWithClaims(checkLoginRequest.Token, &UserWithClaimsRaw{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Println("Returning wrong signing method")
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(bCryptSecret), nil
	})

	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	// If signature is invalid: tell user
	checkLoginResponse.SignatureValid = token.Valid
	if !token.Valid {
		uhttp.RenderError(w, r, fmt.Errorf("Token invalid (signature)"), nil)
		return
	}

	// Extract claims and use validity check
	if userWithClaims, ok := token.Claims.(*UserWithClaimsRaw); ok {
		checkLoginResponse.User = userWithClaims.ToUser()
		err = checkLoginResponse.User.UnmarshalAdditionalAttributes()
		if err != nil {
			log.Infof("Could not unmarshal (%s)", err)
		}
		checkLoginResponse.ContainsRequiredAttributes = true
		checkLoginResponse.IssuedBeforeNow = userWithClaims.IssuedAt <= int64(time.Now().Unix())
		checkLoginResponse.ExpiryAfterNow = userWithClaims.ExpiresAt >= int64(time.Now().Unix())
	}

	checkLoginResponse.Valid = checkLoginResponse.AllOk()
	if !checkLoginResponse.Valid {
		w.WriteHeader(http.StatusUnauthorized)
	}
	err = json.NewEncoder(w).Encode(checkLoginResponse)
	if err != nil {
		log.Errorf("Error rendering response (%s)", err)
	}
})

// CheckLoginHandler for testing a user's webtoken
var CheckLoginHandler = uhttp.Handler{
	PostHandler: checkLoginHandler,
}
