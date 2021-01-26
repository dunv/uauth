package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dunv/uauth"
	"github.com/dunv/uhelpers"
	"github.com/dunv/uhttp"
	"golang.org/x/crypto/bcrypt"
)

type createUserModel struct {
	UserName             string           `bson:"userName" json:"userName"`
	FirstName            string           `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName             string           `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Password             string           `bson:"password" json:"password,omitempty"`
	AdditionalAttributes *json.RawMessage `bson:"additionalAttributes" json:"additionalAttirbutes,omitempty"`
	Roles                []string         `bson:"roles" json:"roles"`
}

var CreateUserHandler = uhttp.NewHandler(
	uhttp.WithMiddlewares(uauth.AuthJWT()),
	uhttp.WithPostModel(
		createUserModel{},
		func(r *http.Request, model interface{}, returnCode *int) interface{} {
			user, err := uauth.UserFromRequest(r)
			if err != nil {
				return err
			}
			if !user.CheckPermission(uauth.CanCreateUsers) {
				return fmt.Errorf("User does not have the required permission: %s", uauth.CanCreateUsers)
			}

			// Parse requestedUserModel
			userFromRequest := model.(*createUserModel)

			// Verify all roles exist
			roleService := uauth.NewRoleService(uauth.UserDB(r), uauth.UserDBName(r))
			allRoles, err := roleService.List()
			if err != nil {
				return err
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
				return fmt.Errorf("Not all desired roles for the new user are valid")
			}

			hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(userFromRequest.Password), 12)
			if err != nil {
				return err
			}

			userService := uauth.NewUserService(uauth.UserDB(r), uauth.UserDBName(r))
			userToBeCreated := uauth.User{
				UserName:  userFromRequest.UserName,
				FirstName: userFromRequest.FirstName,
				LastName:  userFromRequest.LastName,
				Password:  uhelpers.PtrToString(string(hashedPasswordBytes)),
				Roles:     &verifiedRoles,
			}
			err = userService.CreateUser(&userToBeCreated)
			if err != nil {
				return err
			}

			return map[string]string{"msg": "created successfully"}
		},
	),
)
