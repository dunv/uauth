package uauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
)

var listRolesHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	if !user.CheckPermission(CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanReadUsers))
		return
	}

	// Get DB
	db := r.Context().Value(UserDB).(*mongo.Client)
	roleService := NewRoleService(db)
	rolesFromDb, err := roleService.List()

	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	err = json.NewEncoder(w).Encode(*rolesFromDb)
	if err != nil {
		log.Errorf("Error rendering response (%s)", err)
	}
})

// ListRolesHandler <-
var ListRolesHandler = uhttp.Handler{
	GetHandler:   listRolesHandler,
	DbRequired:   []uhttp.ContextKey{UserDB},
	AuthRequired: true,
}
