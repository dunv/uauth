package uauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/mongo"
)

var listUsersHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	if !user.CheckPermission(CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanReadUsers), nil)
		return
	}

	// Get DB
	db := r.Context().Value(UserDB).(*mongo.Client)
	userService := NewUserService(db)
	usersFromDb, err := userService.List()

	if err != nil {
		uhttp.RenderError(w, r, err, nil)
		return
	}

	// Strip passwords
	users := *usersFromDb
	for index := range users {
		user := &users[index]
		user.Password = nil
	}

	json.NewEncoder(w).Encode(*usersFromDb)
	return
})

// ListUsersHandler <-
var ListUsersHandler = uhttp.Handler{
	Methods:      []string{"GET"},
	Handler:      listUsersHandler,
	DbRequired:   []uhttp.ContextKey{UserDB},
	AuthRequired: true,
}
