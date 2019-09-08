package models

import (
	"encoding/json"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dunv/uauth/interfaces"
	"github.com/dunv/uauth/permissions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserWithClaims for JWT
type UserWithClaims struct {
	ID                      *primitive.ObjectID                          `json:"id,omitempty"`
	UserName                string                                       `json:"userName"`
	FirstName               string                                       `json:"firstName"`
	LastName                string                                       `json:"lastName"`
	Permissions             *[]permissions.Permission                    `json:"permissions"`
	Roles                   *[]string                                    `json:"roles"`
	AdditionalAttributesRaw bson.Raw                                     `json:"-"`
	AdditionalAttributes    interfaces.AdditionalUserAttributesInterface `json:"additionalAttributes,omitempty"`
	jwt.StandardClaims
}

// ToUser creates a User model from a UserWithClaims model
func (u *UserWithClaims) ToUser() User {
	return User{
		ID:                   u.ID,
		UserName:             u.UserName,
		FirstName:            u.FirstName,
		LastName:             u.LastName,
		Permissions:          u.Permissions,
		AdditionalAttributes: u.AdditionalAttributes,
		Roles:                u.Roles,
	}
}
func (u *UserWithClaims) UnmarshalAdditionalAttributes() error {
	if u.AdditionalAttributesRaw != nil && AdditionalAttributesModel != nil {
		additionalAttributes := AdditionalAttributesModel.CloneEmpty()
		err := bson.Unmarshal(u.AdditionalAttributesRaw, additionalAttributes)
		if err != nil {
			return fmt.Errorf("could not unmarshal %s", err)
		}
		u.AdditionalAttributes = additionalAttributes
	}
	return nil
}

type UserWithClaimsRaw struct {
	ID                      *primitive.ObjectID                          `json:"id,omitempty"`
	UserName                string                                       `json:"userName"`
	FirstName               string                                       `json:"firstName"`
	LastName                string                                       `json:"lastName"`
	Permissions             *[]permissions.Permission                    `json:"permissions"`
	Roles                   *[]string                                    `json:"roles"`
	AdditionalAttributesRaw json.RawMessage                              `json:"additionalAttributes"`
	AdditionalAttributes    interfaces.AdditionalUserAttributesInterface `json:"-"`
	jwt.StandardClaims
}

// ToUser creates a User model from a UserWithClaims model
func (u *UserWithClaimsRaw) ToUser() User {
	return User{
		ID:                   u.ID,
		UserName:             u.UserName,
		FirstName:            u.FirstName,
		LastName:             u.LastName,
		Permissions:          u.Permissions,
		AdditionalAttributes: u.AdditionalAttributes,
		Roles:                u.Roles,
	}
}

func (u *UserWithClaimsRaw) UnmarshalAdditionalAttributes() error {
	if AdditionalAttributesModel != nil {
		additionalAttributes := AdditionalAttributesModel.CloneEmpty()
		if u.AdditionalAttributesRaw != nil {
			err := json.Unmarshal(u.AdditionalAttributesRaw, additionalAttributes)
			if err != nil {
				return fmt.Errorf("could not unmarshal (%s)", err)
			}
			u.AdditionalAttributes = additionalAttributes
		} else if AdditionalAttributesModel != nil {
			u.AdditionalAttributes = additionalAttributes
		}
	}
	return nil
}
