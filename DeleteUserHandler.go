package uauth

import (
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var deleteUserHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	if !user.CheckPermission(CanDeleteUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanDeleteUsers))
		return
	}

	// Get Params
	params := r.Context().Value(uhttp.CtxKeyParams).(map[string]interface{})

	// Get DB
	db := r.Context().Value(UserDB).(*mongo.Client)
	service := NewUserService(db)

	ID, err := primitive.ObjectIDFromHex(params["userId"].(string))
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
	return
})

// DeleteUserHandler <-
var DeleteUserHandler = uhttp.Handler{
	DeleteHandler: deleteUserHandler,
	DbRequired:    []uhttp.ContextKey{UserDB},
	AuthRequired:  true,
	RequiredParams: uhttp.Params{ParamMap: map[string]uhttp.ParamRequirement{
		"userId": uhttp.ParamRequirement{AllValues: true},
	}},
}
