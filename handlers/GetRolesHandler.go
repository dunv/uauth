package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

type rolesGetResponse struct {
	Roles   *[]uauth.Role `json:"roles"`
	Success bool          `json:"success"`
}

// RolesGetHandler for getting days for the logged in user
var GetRolesHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	GetHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.UserFromRequest(r)
		if !user.CheckPermission(uauth.CanReadUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", uauth.CanReadUsers))
			return
		}

		// Get Roles
		rolesService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
		roles, err := rolesService.GetMultipleByName(*user.Roles)

		// Check error
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Encode response
		uhttp.Render(w, r, rolesGetResponse{
			Success: true,
			Roles:   roles,
		})
	}),
}
