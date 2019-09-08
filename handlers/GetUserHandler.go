package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

var getUserHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(config.CtxKeyUser).(models.User)

	if !user.CheckPermission(permissions.CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanReadUsers))
		return
	}

	// Get Params
	params := r.Context().Value(uhttp.CtxKeyParams).(map[string]interface{})

	// Get DB
	db := r.Context().Value(config.CtxKeyUserDB).(*mongo.Client)
	service := services.NewUserService(db)

	ID, err := primitive.ObjectIDFromHex(params["userId"].(string))
	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}
	userFromDb, err := service.Get(ID)

	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	userFromDb.Password = nil

	err = json.NewEncoder(w).Encode(*userFromDb)
	if err != nil {
		ulog.Errorf("Error rendering response (%s)", err)
	}
})

var GetUserHandler = uhttp.Handler{
	GetHandler:   getUserHandler,
	DbRequired:   []uhttp.ContextKey{config.CtxKeyUserDB},
	AuthRequired: true,
	RequiredParams: uhttp.Params{ParamMap: map[string]uhttp.ParamRequirement{
		"userId": uhttp.ParamRequirement{AllValues: true},
	}},
}
