package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var ListUsersHandler = uhttp.NewHandler(
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

		userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		usersFromDb, err := userService.List()

		if err != nil {
			return err
		}

		// Strip passwords
		users := *usersFromDb
		for index := range users {
			user := &users[index]
			user.Password = nil
		}

		return *usersFromDb
	}),
)
