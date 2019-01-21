package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gopkg.in/mgo.v2/bson"

	"github.com/dunv/mongo"
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
		uhttp.RenderError(w, r, err)
		return
	}

	// Get DB
	db := r.Context().Value(uhttp.CtxKeyDB).(*mongo.DbSession)
	service := NewUserService(db)
	// Load user to check if it exists!
	userFromDb, err := service.Get(bson.ObjectIdHex(userFromRequest.ID))
	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	// Check permission if not modifying "own user"
	if user.ID != userFromDb.ID && !user.CheckPermission(CanUpdateUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanUpdateUsers))
		return
	}

	// Delete roles if permissions not adequate
	if !user.CheckPermission(CanUpdateUsers) {
		userFromRequest.Roles = nil
	}

	// Verify all roles exist
	if userFromRequest.Roles != nil {
		roleService := NewRoleService(db)
		allRoles, err := roleService.GetAllRoles()
		if err != nil {
			uhttp.RenderError(w, r, err)
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
			uhttp.RenderError(w, r, fmt.Errorf("Not all desired roles for the new user are valid"))
			return
		}
	}

	var hashedPassword string
	if userFromRequest.Password != nil {
		hashedPassword, _ = HashPassword(*userFromRequest.Password)
		userFromRequest.Password = &hashedPassword
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}
	}

	err = service.Update(bson.ObjectIdHex(userFromRequest.ID), userFromRequest)
	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	uhttp.RenderMessageWithStatusCode(w, r, 200, "Updated successfully")
})

// UpdateUserHandler <-
var UpdateUserHandler = uhttp.Handler{
	Methods:      []string{"OPTIONS", "POST"},
	Handler:      updateUserHandler,
	DbRequired:   true,
	AuthRequired: true,
}
