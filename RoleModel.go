package uauth

import "go.mongodb.org/mongo-driver/bson/primitive"

// Role role
type Role struct {
	ID          *primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Name        string              `bson:"name" json:"name"`
	Permissions []Permission        `bson:"permissions" json:"permissions"`
}

// MergeToPermissions figure out which permissions result in "having multiple roles"
func MergeToPermissions(roles []Role) []Permission {
	dict := map[Permission]bool{}
	model := []Permission{}

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
