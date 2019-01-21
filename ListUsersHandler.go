package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/mongo"
	"github.com/dunv/uhttp"
)

var listUsersHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Get User
	user := r.Context().Value(CtxKeyUser).(User)

	if !user.CheckPermission(CanReadUsers) {
		uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", CanReadUsers))
		return
	}

	// Get DB
	db := r.Context().Value(uhttp.CtxKeyDB).(*mongo.DbSession)
	userService := NewUserService(db)
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

	json.NewEncoder(w).Encode(*usersFromDb)
	return
})

// ListUsersHandler <-
var ListUsersHandler = uhttp.Handler{
	Methods:      []string{"GET"},
	Handler:      listUsersHandler,
	DbRequired:   true,
	AuthRequired: true,
}
