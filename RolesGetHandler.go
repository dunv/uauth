package uauth

import (
	"encoding/json"
	"net/http"

	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/mongo"
)

type rolesGetResponse struct {
	Roles   *[]Role `json:"roles"`
	Success bool    `json:"success"`
}

// RolesGetHandler for getting days for the logged in user
var RolesGetHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	// Get Roles
	db := r.Context().Value(UserDB).(*mongo.Client)
	rolesService := NewRoleService(db)
	roles, err := rolesService.GetMultipleByName(*user.Roles)

	// Check error
	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	// Encode response
	json.NewEncoder(w).Encode(rolesGetResponse{
		Success: true,
		Roles:   roles,
	})
})
