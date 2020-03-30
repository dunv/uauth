package uauth

import (
	"fmt"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                   *primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	UserName             string              `bson:"userName" json:"userName"`
	FirstName            string              `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName             string              `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Password             *string             `bson:"password,omitempty" json:"password,omitempty"`
	Roles                *[]string           `bson:"roles" json:"roles,omitempty"`
	Permissions          *[]Permission       `bson:"-" json:"permissions,omitempty"`
	AdditionalAttributes interface{}         `bson:"additionalAttributes,omitempty" json:"additionalAttributes,omitempty"`
	RefreshTokens        *[]string           `bson:"refreshTokens,omitempty" json:"refreshTokens,omitempty"`
}

func (u *User) CleanForUI(resolvedRoles *[]Role) (*User, error) {
	rolesDict := map[string][]Permission{}
	for _, role := range *resolvedRoles {
		rolesDict[role.Name] = role.Permissions
	}
	uniquePermissions := map[Permission]bool{}
	listPermissions := []Permission{}
	if u.Roles != nil {
		for _, role := range *u.Roles {
			resolvedRole, ok := rolesDict[role]
			if !ok {
				return nil, fmt.Errorf("could not resolve role %s", role)
			}
			for _, permission := range resolvedRole {
				uniquePermissions[permission] = true
			}
		}
		for permission := range uniquePermissions {
			listPermissions = append(listPermissions, permission)
		}
	}

	return &User{
		ID:                   u.ID,
		UserName:             u.UserName,
		FirstName:            u.FirstName,
		LastName:             u.LastName,
		Roles:                u.Roles,
		Permissions:          &listPermissions,
		AdditionalAttributes: u.AdditionalAttributes,
	}, nil
}

// func (u *User) String() string {
// 	return fmt.Sprintf("User{id:'%s' userName:'%s' firstName:'%s' lastName:'%s' roles:'%s'}", u.ID, u.UserName, u.FirstName, u.LastName, *u.Roles)
// }

// CheckPassword checks a password hash of a user
func (u *User) CheckPassword(plainTextPassword string) bool {
	if u.Password == nil {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte(plainTextPassword))
	return err == nil
}

// CheckPermission check if user has a permission
func (u *User) CheckPermission(permission Permission) bool {
	for _, userPerm := range *u.Permissions {
		if userPerm == permission {
			return true
		}
	}
	return false
}
