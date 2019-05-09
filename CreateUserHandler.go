package uauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/mongo"
)

type createUserModel struct {
	UserName  string   `bson:"userName" json:"userName"`
	FirstName string   `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName  string   `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Password  string   `bson:"password" json:"password,omitempty"`
	Roles     []string `bson:"roles" json:"roles"`
}

var createUserHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	if !user.CheckPermission(CanCreateUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanCreateUsers), nil)
		return
	}

	// Parse requestedUserModel
	var userFromRequest createUserModel
	err := json.NewDecoder(r.Body).Decode(&userFromRequest)
	defer r.Body.Close()
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	// Get DB
	db := r.Context().Value(UserDB).(*mongo.Client)

	// Verify all roles exist
	roleService := NewRoleService(db)
	allRoles, err := roleService.GetAllRoles()
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	verifiedRoles := []string{}
	for _, wantedRole := range userFromRequest.Roles {
		for _, existingRole := range *allRoles {
			if wantedRole == existingRole.Name {
				verifiedRoles = append(verifiedRoles, wantedRole)
			}
		}
	}

	if len(verifiedRoles) != len(userFromRequest.Roles) {
		uhttp.RenderError(w, r, fmt.Errorf("Not all desired roles for the new user are valid"), nil)
		return
	}

	hashedPassword, _ := HashPassword(userFromRequest.Password)
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	userService := NewUserService(db)
	userToBeCreated := User{
		UserName:  userFromRequest.UserName,
		FirstName: userFromRequest.FirstName,
		LastName:  userFromRequest.LastName,
		Password:  &hashedPassword,
		Roles:     &verifiedRoles,
	}
	err = userService.CreateUser(&userToBeCreated)
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	uhttp.RenderMessageWithStatusCode(w, r, 200, "Created successfully", nil)
})

// CreateUserHandler <-
var CreateUserHandler = uhttp.Handler{
	Methods:      []string{"OPTIONS", "POST"},
	Handler:      createUserHandler,
	DbRequired:   []uhttp.ContextKey{UserDB},
	AuthRequired: true,
}
