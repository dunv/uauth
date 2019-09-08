package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/permissions"
	"github.com/dunv/ulog"

	"go.mongodb.org/mongo-driver/mongo"
)

const (
	adminRoleName = "userAdmin"
)

// CreateInitialRolesIfNotExist roles if non-existant
func CreateInitialRolesIfNotExist(s *mongo.Client) {
	roleService := NewRoleService(s)
	allRoles, err := roleService.List()
	if err != nil {
		ulog.Infof("Error loading roles (%s) \n", err)
		return
	}

	if len(*allRoles) == 0 {
		ulog.Info("Creating initial roles (auth)...")
		roles := []models.Role{models.Role{
			Name: adminRoleName,
			Permissions: []permissions.Permission{
				permissions.CanReadUsers,
				permissions.CanCreateUsers,
				permissions.CanUpdateUsers,
				permissions.CanDeleteUsers,
			},
		}}
		for _, role := range roles {
			ulog.Infof("role: %s", role.Name)
			err = roleService.CreateRole(&role)
			if err != nil {
				ulog.Errorf("Error creating role (%s)", err)
			}
		}
		ulog.Info("Done.")
	}
}

// CreateInitialUsersIfNotExist creates users if non-existant
func CreateInitialUsersIfNotExist(s *mongo.Client) {
	userService := NewUserService(s)

	allUsers, err := userService.List()
	if err != nil {
		ulog.Infof("Error loading users (%s)", err)
		return
	}

	if len(*allUsers) == 0 {
		ulog.Info("Creating initial users (auth)...")
		roleList := []string{adminRoleName}
		users := []models.User{models.User{
			FirstName: "Default",
			LastName:  "Admin",
			UserName:  "admin",
			Roles:     &roleList,
		}}
		for _, user := range users {
			pw := randStr(15)
			hashedPassword, _ := user.HashPassword(pw)
			user.Password = &hashedPassword
			ulog.Infof("user: %s, pw: %s", user.UserName, pw)
			err = userService.CreateUser(&user)
			if err != nil {
				ulog.Errorf("Error creating user (%s)", err)
			}
		}
		ulog.Infof("Done.")
	}
}

// CreateCustomRolesIfNotExist <-
func CreateCustomRolesIfNotExist(s *mongo.Client, wantedRoles []models.Role, identifier string) error {
	roleService := NewRoleService(s)
	allRoles, err := roleService.List()
	if err != nil {
		ulog.Infof("Error loading roles (%s)", err)
		return fmt.Errorf("Error loading roles")
	}

	missingRoles := []models.Role{}
	found := false
	for _, wantedRole := range wantedRoles {
		found = false
		for _, existingRole := range *allRoles {
			if wantedRole.Name == existingRole.Name {
				found = true
				break
			}
		}
		if !found {
			missingRoles = append(missingRoles, wantedRole)
		}
	}

	if len(missingRoles) != 0 {
		ulog.Infof("Creating initial roles (%s)... \n", identifier)
		for _, role := range missingRoles {
			ulog.Infof("role: %s", role.Name)
			roleService.CreateRole(&role) // nolint
		}
		ulog.Info("Done.")
	}

	return nil
}

func randStr(len int) string {
	buff := make([]byte, len)
	_, err := rand.Read(buff)
	if err != nil {
		ulog.Errorf("Error creating random number (%s)", err)
	}
	str := base64.StdEncoding.EncodeToString(buff)
	// Base 64 can be longer than len
	return str[:len]
}
