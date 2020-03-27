package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var ListUsersHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	GetHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.UserFromRequest(r)
		if !user.CheckPermission(uauth.CanReadUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", uauth.CanReadUsers))
			return
		}

		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
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
