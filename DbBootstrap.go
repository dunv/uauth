package uauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/dunv/uhelpers"
	"github.com/dunv/ulog"
	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/mongo"
)

const (
	adminRoleName = "userAdmin"
)

// CreateInitialRolesIfNotExist roles if non-existant
func CreateInitialRolesIfNotExist(s *mongo.Client, dbName string) error {
	roleService := NewRoleService(s, dbName)
	err := roleService.EnsureIndexes()
	if err != nil {
		return err
	}

	allRoles, err := roleService.List()
	if err != nil {
		return fmt.Errorf("Error loading roles (%s) \n", err)
	}

	if len(*allRoles) == 0 {
		ulog.Infof("Creating initial roles (auth)...")
		roles := []Role{{
			Name: adminRoleName,
			Permissions: []Permission{
				CanReadUsers,
				CanCreateUsers,
				CanUpdateUsers,
				CanDeleteUsers,
			},
		}}
		for _, role := range roles {
			ulog.Infof("role: %s", role.Name)
			err = roleService.CreateRole(&role)
			if err != nil {
				return fmt.Errorf("could not create role %s (%s)", role.Name, err)
			}
		}
		ulog.Info("Done.")
	}

	return nil
}

// CreateInitialUsersIfNotExist creates users if non-existant
func CreateInitialUsersIfNotExist(s *mongo.Client, dbName string) error {
	userService := NewUserService(s, dbName)
	err := userService.EnsureIndexes()
	if err != nil {
		return err
	}

	allUsers, err := userService.List()
	if err != nil {
		return fmt.Errorf("Error loading users (%s)", err)
	}

	if len(*allUsers) == 0 {
		ulog.Info("Creating initial users (auth)...")
		roleList := []string{adminRoleName}
		users := []User{{
			FirstName: "Default",
			LastName:  "Admin",
			UserName:  "admin",
			Roles:     &roleList,
		}}
		for _, user := range users {
			pw := randStr(15)
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
			if err != nil {
				return fmt.Errorf("could not create user %s (%s)", user.UserName, err)
			}
			user.Password = uhelpers.PtrToString(string(hashedPassword))
			ulog.Infof("user: %s, pw: %s", user.UserName, pw)
			err = userService.CreateUser(&user)
			if err != nil {
				return fmt.Errorf("could not create user %s (%s)", user.UserName, err)
			}
		}
		ulog.Infof("Done.")
	}
	return nil
}

func CreateCustomRolesIfNotExist(s *mongo.Client, dbName string, wantedRoles []Role, identifier string) error {
	roleService := NewRoleService(s, dbName)
	allRoles, err := roleService.List()
	if err != nil {
		return fmt.Errorf("Error loading roles")
	}

	missingRoles := []Role{}
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
		ulog.Infof("Creating initial roles (%s)...", identifier)
		for _, role := range missingRoles {
			ulog.Infof("role: %s", role.Name)
			err = roleService.CreateRole(&role)
			if err != nil {
				return fmt.Errorf("could not create role %s (%s)", role.Name, err)
			}
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
