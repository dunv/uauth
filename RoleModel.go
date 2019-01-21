package uauth

import "gopkg.in/mgo.v2/bson"

// Role role
type Role struct {
	ID          bson.ObjectId `bson:"_id" json:"id,omitempty"`
	Name        string        `bson:"name" json:"name"`
	Permissions []Permission  `bson:"permissions" json:"permissions"`
	// CanCreateUsers             bool `bson:"canCreateUsers" json:"canCreateUsers"`
	// CanUpdateUsers             bool `bson:"canUpdateUsers" json:"canUpdateUsers"`
	// CanDeleteUsers             bool `bson:"canDeleteUsers" json:"canDeleteUsers"`
	// CanCreateDays              bool `bson:"canCreateDays" json:"canCreateDays"`
	// CanUpdateDays              bool `bson:"canUpdateDays" json:"canUpdateDays"`
	// CanDeleteDays              bool `bson:"canDeleteDays" json:"canDeleteDays"`
	// CanCreateDaysForOtherUsers bool `bson:"canCreateDaysForOtherUsers" json:"canCreateDaysForOtherUsers"`
	// CanUpdateDaysForOtherUsers bool `bson:"canUpdateDaysForOtherUsers" json:"canUpdateDaysForOtherUsers"`
	// CanDeleteDaysForOtherUsers bool `bson:"canDeleteDaysForOtherUsers" json:"canDeleteDaysForOtherUsers"`
}

// GenerateID generates a random ID for the document
func (r *Role) GenerateID() {
	newID := bson.NewObjectId()
	r.ID = newID
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
