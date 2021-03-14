package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

// RolesGetHandler for getting days for the logged in user
var GetRolesHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT(), uauth.CheckPermissions(uauth.CanReadUsers)),
	uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			return err
		}

		// Get Roles
		rolesService := uauth.GetRoleService(r)
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
