package uauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/dunv/uhttp"
)

var getUserHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	if !user.CheckPermission(CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanReadUsers), nil)
		return
	}

	// Get Params
	params := r.Context().Value(uhttp.CtxKeyParams).(map[string]interface{})

	// Get DB
	db := r.Context().Value(UserDB).(*mongo.Client)
	service := NewUserService(db)

	ID, err := primitive.ObjectIDFromHex(params["userId"].(string))
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}
	userFromDb, err := service.Get(ID)

	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	userFromDb.Password = nil

	json.NewEncoder(w).Encode(*userFromDb)
	return
})

// GetUserHandler <-
var GetUserHandler = uhttp.Handler{
	GetHandler:   getUserHandler,
	DbRequired:   []uhttp.ContextKey{UserDB},
	AuthRequired: true,
	RequiredParams: uhttp.Params{ParamMap: map[string]uhttp.ParamRequirement{
		"userId": uhttp.ParamRequirement{AllValues: true},
	}},
}
