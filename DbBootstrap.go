package uauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	log "github.com/sirupsen/logrus"

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
		log.Printf("Error loading roles (%s) \n", err)
		return
	}

	if len(*allRoles) == 0 {
		log.Println("Creating initial roles (auth)...")
		roles := []Role{Role{
			Name: adminRoleName,
			Permissions: []Permission{
				CanReadUsers,
				CanCreateUsers,
				CanUpdateUsers,
				CanDeleteUsers,
			},
		}}
		for _, role := range roles {
			log.Printf("role: %s", role.Name)
			err = roleService.CreateRole(&role)
			if err != nil {
				log.Errorf("Error creating role (%s)", err)
			}
		}
		log.Println("Done.")
	}
}

// CreateInitialUsersIfNotExist creates users if non-existant
func CreateInitialUsersIfNotExist(s *mongo.Client) {
	userService := NewUserService(s)

	allUsers, err := userService.List()
	if err != nil {
		log.Printf("Error loading users (%s)", err)
		return
	}

	if len(*allUsers) == 0 {
		log.Println("Creating initial users (auth)...")
		roleList := []string{adminRoleName}
		users := []User{User{
			FirstName: "Default",
			LastName:  "Admin",
			UserName:  "admin",
			Roles:     &roleList,
		}}
		for _, user := range users {
			pw := randStr(15)
			hashedPassword, _ := user.HashPassword(pw)
			user.Password = &hashedPassword
			log.Printf("user: %s, pw: %s", user.UserName, pw)
			err = userService.CreateUser(&user)
			if err != nil {
				log.Errorf("Error creating user (%s)", err)
			}
		}
		log.Println("Done.")
	}
}

// CreateCustomRolesIfNotExist <-
func CreateCustomRolesIfNotExist(s *mongo.Client, wantedRoles []Role, identifier string) error {
	roleService := NewRoleService(s)
	allRoles, err := roleService.List()
	if err != nil {
		log.Printf("Error loading roles (%s)", err)
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
		log.Printf("Creating initial roles (%s)... \n", identifier)
		for _, role := range missingRoles {
			log.Printf("role: %s", role.Name)
			roleService.CreateRole(&role) // nolint
		}
		log.Println("Done.")
	}

	return nil
}

func randStr(len int) string {
	buff := make([]byte, len)
	_, err := rand.Read(buff)
	if err != nil {
		log.Errorf("Error creating random number (%s)", err)
	}
	str := base64.StdEncoding.EncodeToString(buff)
	// Base 64 can be longer than len
	return str[:len]
}
