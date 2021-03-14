package handlers

import (
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var DeleteUserHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT(), uauth.CheckPermissions(uauth.CanDeleteUsers)),
	uhttp.WithRequiredGet(uhttp.R{"userId": uhttp.STRING}),
	uhttp.WithDelete(func(r *http.Request, returnCode *int) interface{} {
		service := uauth.GetUserService(r)
		ID, err := primitive.ObjectIDFromHex(*uhttp.GetAsString("userId", r))
		if err != nil {
			return err
		}

		err = service.Delete(ID)
		if err != nil {
			return err
		}

		return map[string]string{"msg": "Deleted successfully"}
	}),
)
