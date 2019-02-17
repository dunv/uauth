package uauth

import (
	"time"

	"gopkg.in/mgo.v2/bson"
)

// RecordTrail <-
type RecordTrail struct {
	Owner      *string    `bson:"owner,omitempty" json:"owner,omitempty"`
	CreatedBy  *string    `bson:"createdBy,omitempty" json:"createdBy,omitempty"`
	CreatedAt  *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	ModifiedBy *string    `bson:"modifiedBy,omitempty" json:"modifiedBy,omitempty"`
	ModifiedAt *time.Time `bson:"modifiedAt,omitempty" json:"modifiedAt,omitempty"`
}

// GenerateUpdateModifiedStatement <-
func GenerateUpdateModifiedStatement(time time.Time, user User) bson.M {
	return bson.M{
		"recordTrail.modifiedAt": time,
		"recordTrail.modifiedBy": user.UserName,
	}
}
