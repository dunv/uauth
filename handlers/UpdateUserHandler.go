package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhelpers"
	"github.com/dunv/uhttp"
	"golang.org/x/crypto/bcrypt"
)

var UpdateUserHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT()),
	uhttp.WithPostModel(uauth.User{}, func(r *http.Request, model interface{}, returnCode *int) interface{} {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			return err
		}

		// Parse requestedUserModel
		userFromRequest := model.(*uauth.User)
		service := uauth.GetUserService(r)

		// Load user to check if it exists!
		if user.ID == nil {
			return fmt.Errorf("UserID is not set")
		}

		userFromDb, err := service.Get(*userFromRequest.ID)
		if err != nil {
			return err
		}

		// Check permission if not modifying "own user"
		if user.ID != userFromDb.ID && !user.CheckPermission(uauth.CanUpdateUsers) {
			return fmt.Errorf("User does not have the required permission: %s", uauth.CanUpdateUsers)
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
				return err
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
				return fmt.Errorf("Not all desired roles for the new user are valid")
			}
		}

		if userFromRequest.Password != nil {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*userFromRequest.Password), 12)
			if err != nil {
				return err
			}
			userFromRequest.Password = uhelpers.PtrToString(string(hashedPassword))
		}

		// Make sure username cannot change
		userFromRequest.UserName = userFromDb.UserName

		err = service.Update(*userFromRequest)
		if err != nil {
			return err
		}

		return map[string]string{"msg": "Updated successfully"}
	}),
)
