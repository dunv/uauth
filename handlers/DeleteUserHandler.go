package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var DeleteUserHandler = uhttp.Handler{
	AddMiddleware: uauth.AuthJWT(),
	RequiredGet: uhttp.R{
		"userId": uhttp.STRING,
	},
	DeleteHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := uauth.UserFromRequest(r)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}
		if !user.CheckPermission(uauth.CanDeleteUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", uauth.CanDeleteUsers))
			return
		}

		service := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
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
