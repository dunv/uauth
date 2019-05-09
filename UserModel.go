package uauth

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User user
type User struct {
	ID          *primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	UserName    string        `bson:"userName" json:"userName"`
	FirstName   string        `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName    string        `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Password    *string       `bson:"password" json:"password,omitempty"`
	Permissions *[]Permission `bson:"-" json:"permissions,omitempty"`
	Roles       *[]string     `bson:"roles" json:"roles,omitempty"`
}

// UpdateUserModel for updating parts of a user
type UpdateUserModel struct {
	ID        string    `bson:"-" json:"id"`
	FirstName *string   `bson:"firstName,omitempty" json:"firstName,omitempty"`
	LastName  *string   `bson:"lastName,omitempty" json:"lastName,omitempty"`
	Password  *string   `bson:"password,omitempty" json:"password,omitempty"`
	Roles     *[]string `bson:"roles,omitempty" json:"roles,omitempty"`
}

func (u User) String() string {
	return fmt.Sprintf("User{id:'%s' userName:'%s' firstName:'%s' lastName:'%s' roles:'%s'}", u.ID, u.UserName, u.FirstName, u.LastName, *u.Roles)
}

// UserWithClaims for JWT
type UserWithClaims struct {
	ID          *primitive.ObjectID `json:"id,omitempty"`
	UserName    string        `json:"userName"`
	FirstName   string        `json:"firstName"`
	LastName    string        `json:"lastName"`
	Permissions *[]Permission `json:"permissions"`
	Roles       *[]string     `json:"roles"`
	jwt.StandardClaims
}

// ToUserWithClaims creates a WithClaims model from a User model
func (u User) ToUserWithClaims() UserWithClaims {
	return UserWithClaims{
		ID:          u.ID,
		UserName:    u.UserName,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		Permissions: u.Permissions,
		Roles:       u.Roles,
	}
}

// ToUser creates a User model from a UserWithClaims model
func (u UserWithClaims) ToUser() User {
	return User{
		ID:          u.ID,
		UserName:    u.UserName,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		Permissions: u.Permissions,
		Roles:       u.Roles,
	}
}

// HashPassword Creates a passwordHash
// Remove in refactor
func (u User) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// HashPassword Creates a passwordHash
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// CheckPassword checks a password hash of a user
func (u User) CheckPassword(plainTextPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(*u.Password), []byte(plainTextPassword))
	return err == nil
}

// CheckPermission check if user has a permission
func (u User) CheckPermission(permission Permission) bool {
	for _, userPerm := range *u.Permissions {
		if userPerm == permission {
			return true
		}
	}
	return false
}
