package handlers

import (
	"fmt"
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	contextKeys "github.com/dunv/uhttp/contextkeys"
	uhttpModels "github.com/dunv/uhttp/models"
	"go.mongodb.org/mongo-driver/mongo"
)

var listUsersHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(config.CtxKeyUser).(models.User)

	if !user.CheckPermission(permissions.CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanReadUsers))
		return
	}

	// Get DB
	db := r.Context().Value(config.CtxKeyUserDB).(*mongo.Client)
	userService := services.NewUserService(db)
	usersFromDb, err := userService.List()

	if err != nil {
		uhttp.RenderError(w, r, err)
		return
	}

	// Strip passwords
	users := *usersFromDb
	for index := range users {
		user := &users[index]
		user.Password = nil
	}

	uhttp.Render(w, r, *usersFromDb)
})

var ListUsersHandler = uhttpModels.Handler{
	GetHandler:                listUsersHandler,
	AdditionalContextRequired: []contextKeys.ContextKey{config.CtxKeyUserDB},
	AuthRequired:              true,
}
