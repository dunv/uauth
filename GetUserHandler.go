package uauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gopkg.in/mgo.v2/bson"

	"github.com/dunv/uhttp"
	"github.com/dunv/umongo"
)

var getUserHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	if !user.CheckPermission(CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanReadUsers))
		return
	}

	// Get Params
	params := r.Context().Value(uhttp.CtxKeyParams).(map[string]interface{})

	// Get DB
	db := r.Context().Value(uhttp.CtxKeyDB).(*umongo.DbSession)
	service := NewUserService(db)
	userFromDb, err := service.Get(bson.ObjectIdHex(params["userId"].(string)))

	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	userFromDb.Password = nil

	json.NewEncoder(w).Encode(*userFromDb)
	return
})

// GetUserHandler <-
var GetUserHandler = uhttp.Handler{
	Methods:      []string{"GET"},
	Handler:      getUserHandler,
	DbRequired:   true,
	AuthRequired: true,
	RequiredParams: uhttp.Params{ParamMap: map[string]uhttp.ParamRequirement{
		"userId": uhttp.ParamRequirement{AllValues: true},
	}},
}
