package handlers

import (
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
)

var GetUserHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT(), uauth.CheckPermissions(uauth.CanReadUsers)),
	uhttp.WithRequiredGet(uhttp.R{"userId": uhttp.STRING}),
	uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
		service := uauth.GetUserService(r)
		ID, err := primitive.ObjectIDFromHex(*uhttp.GetAsString("userId", r))
		if err != nil {
			return err
		}
		userFromDb, err := service.GetUiUserByUserID(ID)

		if err != nil {
			return err
		}

		userFromDb.Password = nil
		return *userFromDb
	}),
)
