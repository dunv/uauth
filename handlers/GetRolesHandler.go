package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	uhttpModels "github.com/dunv/uhttp/models"
)

type rolesGetResponse struct {
	Roles   *[]models.Role `json:"roles"`
	Success bool           `json:"success"`
}

// RolesGetHandler for getting days for the logged in user
var GetRolesHandler = uhttpModels.Handler{
	AuthRequired: true,
	GetHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.User(r)
		if !user.CheckPermission(permissions.CanReadUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanReadUsers))
			return
		}

		// Get Roles
		rolesService := services.NewRoleService(uauth.UserDB(r))
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
