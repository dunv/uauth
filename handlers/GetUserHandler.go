package handlers

import (
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var GetUserHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares([]uhttp.Middleware{
		uauth.AuthJWT(),
	}),
	uhttp.WithRequiredGet(uhttp.R{
		"userId": uhttp.STRING,
	}),
	uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			return err
		}
		if !user.CheckPermission(uauth.CanReadUsers) {
			return fmt.Errorf("User does not have the required permission: %s", uauth.CanReadUsers)
		}

		service := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		ID, err := primitive.ObjectIDFromHex(*uhttp.GetAsString("userId", r))
		if err != nil {
			return err
		}
		userFromDb, err := service.Get(ID)

		if err != nil {
			return err
		}

		userFromDb.Password = nil
		return *userFromDb
	}),
)
