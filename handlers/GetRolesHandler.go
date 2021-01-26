package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// RolesGetHandler for getting days for the logged in user
var GetRolesHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT()),
	uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			return err
		}
		if !user.CheckPermission(uauth.CanReadUsers) {
			return fmt.Errorf("User does not have the required permission: %s", uauth.CanReadUsers)
		}

		// Get Roles
		rolesService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
		roles, err := rolesService.GetMultipleByName(*user.Roles)

		// Check error
		if err != nil {
			return err
		}

		// Encode response
		return map[string]interface{}{
			"success": true,
			"roles":   roles,
		}
	}),
)
