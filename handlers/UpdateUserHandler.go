package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	uhttpModels "github.com/dunv/uhttp/models"
)

var UpdateUserHandler = uhttpModels.Handler{
	AddMiddleware: uauth.AuthJWT(),
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.User(r)
		if !user.CheckPermission(permissions.CanUpdateUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanUpdateUsers))
			return
		}

		// Parse requestedUserModel
		var userFromRequest models.User
		err := json.NewDecoder(r.Body).Decode(&userFromRequest)
		defer r.Body.Close()
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		service := services.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))

		// Load user to check if it exists!
		if user.ID == nil {
			uhttp.RenderError(w, r, fmt.Errorf("UserID is not set"))
			return
		}

		userFromDb, err := service.Get(*userFromRequest.ID)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Check permission if not modifying "own user"
		if user.ID != userFromDb.ID && !user.CheckPermission(permissions.CanUpdateUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanUpdateUsers))
			return
		}

		// Delete roles if permissions not adequate
		if !user.CheckPermission(permissions.CanUpdateUsers) {
			userFromRequest.Roles = nil
		}

		// Verify all roles exist
		if userFromRequest.Roles != nil {
			roleService := services.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
			allRoles, err := roleService.List()
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
			hashedPassword, _ = helpers.HashPassword(*userFromRequest.Password)
			userFromRequest.Password = &hashedPassword
			if err != nil {
				uhttp.RenderError(w, r, err)
				return
			}
		}

		// Make sure username cannot change
		userFromRequest.UserName = userFromDb.UserName

		err = service.Update(userFromRequest)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		uhttp.RenderMessageWithStatusCode(w, r, 200, "Updated successfully")
	}),
}
