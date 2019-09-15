package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	uhttpModels "github.com/dunv/uhttp/models"
)

var ListUsersHandler = uhttpModels.Handler{
	AuthRequired: true,
	GetHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.User(r)
		if !user.CheckPermission(permissions.CanReadUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanReadUsers))
			return
		}

		userService := services.NewUserService(uauth.UserDB(r))
		usersFromDb, err := userService.List()

		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Strip passwords
		users := *usersFromDb
		for index := range users {
			user := &users[index]
			user.Password = nil
		}

		uhttp.Render(w, r, *usersFromDb)
	}),
}
