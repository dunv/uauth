package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var DeleteUserHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT()),
	uhttp.WithRequiredGet(uhttp.R{
		"userId": uhttp.STRING,
	}),
	uhttp.WithDelete(func(r *http.Request, returnCode *int) interface{} {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			return err
		}
		if !user.CheckPermission(uauth.CanDeleteUsers) {
			return fmt.Errorf("User does not have the required permission: %s", uauth.CanDeleteUsers)
		}

		service := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
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
