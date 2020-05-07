package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var ListRolesHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares([]uhttp.Middleware{
		uauth.AuthJWT(),
	}),
	uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			return err
		}
		if !user.CheckPermission(uauth.CanReadUsers) {
			return fmt.Errorf("User does not have the required permission: %s", uauth.CanReadUsers)
		}

		roleService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
		rolesFromDb, err := roleService.List()

		if err != nil {
			return err
		}

		return *rolesFromDb
	}),
)
