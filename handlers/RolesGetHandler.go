package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/mongo"
)

type rolesGetResponse struct {
	Roles   *[]models.Role `json:"roles"`
	Success bool           `json:"success"`
}

// RolesGetHandler for getting days for the logged in user
var rolesGetHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(config.CtxKeyUser).(models.User)

	// Get Roles
	db := r.Context().Value(config.CtxKeyUserDB).(*mongo.Client)
	rolesService := services.NewRoleService(db)
	roles, err := rolesService.GetMultipleByName(*user.Roles)

	// Check error
	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	// Encode response
	uhttp.Render(w, r, json.NewEncoder(w).Encode(rolesGetResponse{
		Success: true,
		Roles:   roles,
	}))
})

var RolesGetHandler = uhttp.Handler{
	GetHandler:   rolesGetHandler,
	DbRequired:   []uhttp.ContextKey{config.CtxKeyUserDB},
	AuthRequired: true,
}
