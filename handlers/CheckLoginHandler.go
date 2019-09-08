package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uhttp"
	uhttpContextKeys "github.com/dunv/uhttp/contextkeys"
	uhttpModels "github.com/dunv/uhttp/models"
	"github.com/dunv/ulog"
)

type checkLoginRequest struct {
	Token string `json:"token"`
}

type checkLoginResponse struct {
	User                       models.User `json:"user"`
	SignatureValid             bool        `json:"signatureValid"`
	ContainsRequiredAttributes bool        `json:"containsRequiredAttributes"`
	IssuedBeforeNow            bool        `json:"issuedBeforeNow,omitempty"`
	ExpiryAfterNow             bool        `json:"expiryAfterNow,omitempty"`
	Valid                      bool        `json:"valid,omitempty"`
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
		uhttp.RenderError(w, r, err)
		return
	}

	checkLoginResponse := checkLoginResponse{}

	// Parse token and check signature
	bCryptSecret := r.Context().Value(uhttpContextKeys.CtxKeyBCryptSecret).(string)
	token, err := jwt.ParseWithClaims(checkLoginRequest.Token, &models.UserWithClaimsRaw{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			ulog.Infof("Returning wrong signing method")
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(bCryptSecret), nil
	})

	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	// If signature is invalid: tell user
	checkLoginResponse.SignatureValid = token.Valid
	if !token.Valid {
		uhttp.RenderError(w, r, fmt.Errorf("Token invalid (signature)"))
		return
	}

	// Extract claims and use validity check
	if userWithClaims, ok := token.Claims.(*models.UserWithClaimsRaw); ok {
		err = userWithClaims.UnmarshalAdditionalAttributes()
		if err != nil {
			ulog.Infof("Could not unmarshal (%s)", err)
		}
		checkLoginResponse.User = userWithClaims.ToUser()
		checkLoginResponse.ContainsRequiredAttributes = true
		checkLoginResponse.IssuedBeforeNow = userWithClaims.IssuedAt <= int64(time.Now().Unix())
		checkLoginResponse.ExpiryAfterNow = userWithClaims.ExpiresAt >= int64(time.Now().Unix())
	}

	checkLoginResponse.Valid = checkLoginResponse.AllOk()
	if !checkLoginResponse.Valid {
		uhttp.RenderWithStatusCode(w, r, http.StatusUnauthorized, checkLoginResponse)
	} else {
		uhttp.Render(w, r, checkLoginResponse)
	}
})

// CheckLoginHandler for testing a user's webtoken
var CheckLoginHandler = uhttpModels.Handler{
	PostHandler: checkLoginHandler,
}
