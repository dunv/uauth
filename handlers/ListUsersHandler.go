package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var ListUsersHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT(), uauth.CheckPermissions(uauth.CanReadUsers)),
	uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
		userService := uauth.GetUserService(r)
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
