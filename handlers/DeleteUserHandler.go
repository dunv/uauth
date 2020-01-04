package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var DeleteUserHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	RequiredGet: uhttp.R{
		"userId": uhttp.STRING,
	},
	DeleteHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.User(r)
		if !user.CheckPermission(permissions.CanDeleteUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanDeleteUsers))
			return
		}

		service := services.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		ID, err := primitive.ObjectIDFromHex(*uhttp.GetAsString("userId", r))
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		err = service.Delete(ID)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		uhttp.RenderMessageWithStatusCode(w, r, 200, "Deleted successfully")
	}),
}
