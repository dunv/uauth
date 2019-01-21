package uauth

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"github.com/dunv/umongo"
)

const (
	adminRoleName = "userAdmin"
)

// CreateInitialRolesIfNotExist roles if non-existant
func CreateInitialRolesIfNotExist(s *umongo.DbSession) {
	roleService := NewRoleService(s)
	allRoles, err := roleService.GetAllRoles()
	if err != nil {
		log.Println("Error loading roles")
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
			roleService.CreateRole(&role)
		}
		log.Println("Done.")
	}
}

// CreateInitialUsersIfNotExist creates users if non-existant
func CreateInitialUsersIfNotExist(s *umongo.DbSession) {
	userService := NewUserService(s)

	allUsers, err := userService.List()
	if err != nil {
		log.Println("Error loading users")
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
			userService.CreateUser(&user)
		}
		log.Println("Done.")
	}
}

func randStr(len int) string {
	buff := make([]byte, len)
	rand.Read(buff)
	str := base64.StdEncoding.EncodeToString(buff)
	// Base 64 can be longer than len
	return str[:len]
}
