package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dunv/mongo"
	"github.com/dunv/uhttp"
)

type loginRequest struct {
	User User `json:"user"`
}

type loginResponse struct {
	User User   `json:"user"`
	JWT  string `json:"jwt"`
}

var loginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	// Parse request
	loginRequest := loginRequest{}
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	defer r.Body.Close()
	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	db := r.Context().Value(uhttp.CtxKeyDB).(*mongo.DbSession)
	userService := NewUserService(db)
	userFromDb, err := userService.GetByUserName(loginRequest.User.UserName)

	// Verify user with password
	if err != nil || !(*userFromDb).CheckPassword(*loginRequest.User.Password) {
		err = errors.New("No user with this name/password exists")
		uhttp.RenderError(w, r, err)
		return
	}

	// Get Roles
	rolesService := NewRoleService(db)
	roles, err := rolesService.GetMultipleByName(*userFromDb.Roles)

	// // Check error
	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	permissions := MergeToPermissions(roles)

	// Create jwt-token with the username set
	var userWithClaims = (*userFromDb).ToUserWithClaims()
	userWithClaims.IssuedAt = int64(time.Now().Unix())
	userWithClaims.Issuer = "brauen_login"
	userWithClaims.ExpiresAt = int64(time.Now().Unix() + 604800)
	userWithClaims.Permissions = &permissions
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, userWithClaims)

	bCryptSecret := r.Context().Value(uhttp.CtxKeyBCryptSecret).(string)
	signedToken, err := token.SignedString([]byte(bCryptSecret))
	if err != nil {
		uhttp.RenderError(w, r, err)
	}

	// Add rolesDetails to user-model
	(*userFromDb).Permissions = &permissions

	// Clean
	(*userFromDb).Password = nil

	// Render response
	err = json.NewEncoder(w).Encode(loginResponse{
		User: *userFromDb,
		JWT:  signedToken,
	})
})

// LoginHandler handler for getting JSON web token
var LoginHandler = uhttp.Handler{
	Handler:    loginHandler,
	Methods:    []string{"OPTIONS", "POST"},
	DbRequired: true,
}
