package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var ListRolesHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	GetHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.UserFromRequest(r)
		if !user.CheckPermission(uauth.CanReadUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", uauth.CanReadUsers))
			return
		}

		roleService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
		rolesFromDb, err := roleService.List()

		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		uhttp.Render(w, r, *rolesFromDb)
	}),
}
