package uauth

import "golang.org/x/crypto/bcrypt"

// HashPassword Creates a passwordHash
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}
