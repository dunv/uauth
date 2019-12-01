package models

import (
	"github.com/dunv/uauth/permissions"
)

// Role role
type Role struct {
	Name        string                   `bson:"name" json:"name"`
	Permissions []permissions.Permission `bson:"permissions" json:"permissions"`
}

// MergeToPermissions figure out which permissions result in "having multiple roles"
func MergeToPermissions(roles []Role) []permissions.Permission {
	dict := map[permissions.Permission]bool{}
	model := []permissions.Permission{}

	for _, role := range roles {
		for _, permission := range role.Permissions {
			dict[permission] = true
		}
	}

	for permission := range dict {
		model = append(model, permission)
	}

	return model
}
