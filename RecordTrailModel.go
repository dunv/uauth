package uauth

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

type RecordTrail struct {
	Owner      *string    `bson:"owner,omitempty" json:"owner,omitempty"`
	CreatedBy  *string    `bson:"createdBy,omitempty" json:"createdBy,omitempty"`
	CreatedAt  *time.Time `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	ModifiedBy *string    `bson:"modifiedBy,omitempty" json:"modifiedBy,omitempty"`
	ModifiedAt *time.Time `bson:"modifiedAt,omitempty" json:"modifiedAt,omitempty"`
}

func GenerateUpdateModifiedStatement(time time.Time, user User) bson.D {
	return bson.D{{
		Key: "recordTrail.modifiedAt", Value: time,
	}, {
		Key: "recordTrail.modifiedBy", Value: user.UserName,
	}}
}
