package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/mongo"
)

var listRolesHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(config.CtxKeyUser).(models.User)

	if !user.CheckPermission(permissions.CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanReadUsers))
		return
	}

	// Get DB
	db := r.Context().Value(config.CtxKeyUserDB).(*mongo.Client)
	roleService := services.NewRoleService(db)
	rolesFromDb, err := roleService.List()

	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	uhttp.Render(w, r, json.NewEncoder(w).Encode(*rolesFromDb))
})

var ListRolesHandler = uhttp.Handler{
	GetHandler:   listRolesHandler,
	DbRequired:   []uhttp.ContextKey{config.CtxKeyUserDB},
	AuthRequired: true,
}
