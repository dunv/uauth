package uauth

import (
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	"github.com/dunv/umongo"
	"gopkg.in/mgo.v2/bson"
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
	db := r.Context().Value(uhttp.CtxKeyDB).(*umongo.DbSession)
	service := NewUserService(db)

	err := service.Delete(bson.ObjectIdHex(params["userId"].(string)))
	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	uhttp.RenderMessageWithStatusCode(w, r, 200, "Deleted successfully")
	return
})

// DeleteUserHandler <-
var DeleteUserHandler = uhttp.Handler{
	Methods:      []string{"OPTIONS", "DELETE"},
	Handler:      deleteUserHandler,
	DbRequired:   true,
	AuthRequired: true,
	RequiredParams: uhttp.Params{ParamMap: map[string]uhttp.ParamRequirement{
		"userId": uhttp.ParamRequirement{AllValues: true},
	}},
}
