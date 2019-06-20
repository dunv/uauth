package uauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/dunv/uhttp"
)

var updateUserHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	// Parse requestedUserModel
	var userFromRequest UpdateUserModel
	err := json.NewDecoder(r.Body).Decode(&userFromRequest)
	defer r.Body.Close()
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	// Get DB
	db := r.Context().Value(UserDB).(*mongo.Client)
	service := NewUserService(db)
	// Load user to check if it exists!

	ID, err := primitive.ObjectIDFromHex(userFromRequest.ID)
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	userFromDb, err := service.Get(ID)
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	// Check permission if not modifying "own user"
	if user.ID != userFromDb.ID && !user.CheckPermission(CanUpdateUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanUpdateUsers), nil)
		return
	}

	// Delete roles if permissions not adequate
	if !user.CheckPermission(CanUpdateUsers) {
		userFromRequest.Roles = nil
	}

	// Verify all roles exist
	if userFromRequest.Roles != nil {
		roleService := NewRoleService(db)
		allRoles, err := roleService.List()
		if err != nil {
			uhttp.RenderError(w, r, err, nil)
			return
		}
		verifiedRoles := []string{}
		for _, wantedRole := range *userFromRequest.Roles {
			for _, existingRole := range *allRoles {
				if wantedRole == existingRole.Name {
					verifiedRoles = append(verifiedRoles, wantedRole)
				}
			}
		}

		if len(verifiedRoles) != len(*userFromRequest.Roles) {
			uhttp.RenderError(w, r, fmt.Errorf("Not all desired roles for the new user are valid"), nil)
			return
		}
	}

	var hashedPassword string
	if userFromRequest.Password != nil {
		hashedPassword, _ = HashPassword(*userFromRequest.Password)
		userFromRequest.Password = &hashedPassword
		if err != nil {
			uhttp.RenderError(w, r, err, nil)
			return
		}
	}

	err = service.Update(ID, userFromRequest)
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	uhttp.RenderMessageWithStatusCode(w, r, 200, "Updated successfully", nil)
})

// UpdateUserHandler <-
var UpdateUserHandler = uhttp.Handler{
	PostHandler:  updateUserHandler,
	DbRequired:   []uhttp.ContextKey{UserDB},
	AuthRequired: true,
}
