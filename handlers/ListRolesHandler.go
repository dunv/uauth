package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var ListRolesHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT(), uauth.CheckPermissions(uauth.CanReadUsers)),
	uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
		roleService := uauth.GetRoleService(r)
		rolesFromDb, err := roleService.List()
		if err != nil {
			return err
		}

		return *rolesFromDb
	}),
)
