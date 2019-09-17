package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	uhttpModels "github.com/dunv/uhttp/models"
)

type createUserModel struct {
	UserName             string           `bson:"userName" json:"userName"`
	FirstName            string           `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName             string           `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Password             string           `bson:"password" json:"password,omitempty"`
	AdditionalAttributes *json.RawMessage `bson:"additionalAttributes" json:"additionalAttirbutes,omitempty"`
	Roles                []string         `bson:"roles" json:"roles"`
}

var CreateUserHandler = uhttpModels.Handler{
	AddMiddleware: uauth.AuthJWT(),
	PostHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := uauth.User(r)
		if !user.CheckPermission(permissions.CanCreateUsers) {
			uhttp.RenderError(w, r, fmt.Errorf("User does not have the required permission: %s", permissions.CanCreateUsers))
			return
		}

		// Parse requestedUserModel
		var userFromRequest createUserModel
		err := json.NewDecoder(r.Body).Decode(&userFromRequest)
		defer r.Body.Close()
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		// Verify all roles exist
		roleService := services.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
		allRoles, err := roleService.List()
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		verifiedRoles := []string{}
		for _, wantedRole := range userFromRequest.Roles {
			for _, existingRole := range *allRoles {
				if wantedRole == existingRole.Name {
					verifiedRoles = append(verifiedRoles, wantedRole)
				}
			}
		}

		if len(verifiedRoles) != len(userFromRequest.Roles) {
			uhttp.RenderError(w, r, fmt.Errorf("Not all desired roles for the new user are valid"))
			return
		}

		hashedPassword, _ := helpers.HashPassword(userFromRequest.Password)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		userService := services.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
		userToBeCreated := models.User{
			UserName:  userFromRequest.UserName,
			FirstName: userFromRequest.FirstName,
			LastName:  userFromRequest.LastName,
			Password:  &hashedPassword,
			Roles:     &verifiedRoles,
		}
		err = userService.CreateUser(&userToBeCreated)
		if err != nil {
			uhttp.RenderError(w, r, err)
			return
		}

		uhttp.RenderMessageWithStatusCode(w, r, 200, "Created successfully")
	}),
}
