package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhelpers"
	"github.com/dunv/uhttp"
	"golang.org/x/crypto/bcrypt"
)

var UpdateUserHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}
		if !user.CheckPermission(uauth.CanUpdateUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", uauth.CanUpdateUsers))
			return
		}

		// Parse requestedUserModel
		var userFromRequest uauth.User
		err = json.NewDecoder(r.Body).Decode(&userFromRequest)
		defer r.Body.Close()
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		service := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))

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
		if user.ID != userFromDb.ID && !user.CheckPermission(uauth.CanUpdateUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", uauth.CanUpdateUsers))
			return
		}

		// Delete roles if permissions not adequate
		if !user.CheckPermission(uauth.CanUpdateUsers) {
			userFromRequest.Roles = nil
		}

		// Verify all roles exist
		if userFromRequest.Roles != nil {
			roleService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
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

		if userFromRequest.Password != nil {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*userFromRequest.Password), 12)
			if err != nil {
				uhttp.RenderError(w, r, err)
				return
			}
			userFromRequest.Password = uhelpers.PtrToString(string(hashedPassword))
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
