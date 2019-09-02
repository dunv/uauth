package uauth

import (
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// User user
type User struct {
	ID                      *primitive.ObjectID               `bson:"_id" json:"id,omitempty"`
	UserName                string                            `bson:"userName" json:"userName"`
	FirstName               string                            `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName                string                            `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Password                *string                           `bson:"password,omitempty" json:"password,omitempty"`
	Permissions             *[]Permission                     `bson:"-" json:"permissions,omitempty"`
	AdditionalAttributesRaw bson.Raw                          `bson:"additionalAttributes,omitempty" json:"-"`
	AdditionalAttributes    AdditionalUserAttributesInterface `bson:"-"  json:"additionalAttributes,omitempty"`
	Roles                   *[]string                         `bson:"roles" json:"roles,omitempty"`
}

func (u *User) String() string {
	return fmt.Sprintf("User{id:'%s' userName:'%s' firstName:'%s' lastName:'%s' roles:'%s'}", u.ID, u.UserName, u.FirstName, u.LastName, *u.Roles)
}

// ToUserWithClaims creates a WithClaims model from a User model
func (u *User) ToUserWithClaims() UserWithClaims {
	return UserWithClaims{
		ID:                      u.ID,
		UserName:                u.UserName,
		FirstName:               u.FirstName,
		LastName:                u.LastName,
		Permissions:             u.Permissions,
		AdditionalAttributesRaw: u.AdditionalAttributesRaw,
		Roles:                   u.Roles,
	}
}

// HashPassword Creates a passwordHash
// Remove in refactor
func (u *User) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

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

func (u *User) UnmarshalAdditionalAttributes() error {
	if additionalAttributesModel != nil {
		additionalAttributes := additionalAttributesModel.CloneEmpty()
		if u.AdditionalAttributesRaw != nil {
			err := bson.Unmarshal(u.AdditionalAttributesRaw, additionalAttributes)
			if err != nil {
				return fmt.Errorf("could not unmarshal %s", err)
			}
			u.AdditionalAttributes = additionalAttributes
		} else if additionalAttributesModel != nil {
			u.AdditionalAttributes = additionalAttributes
		}
	}
	return nil
}
