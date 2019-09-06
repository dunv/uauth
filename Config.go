package uauth

var userDB string

// SetDatabase for users and roles
func SetDatabase(_userDB string) {
	userDB = _userDB
}

const defaultTokenIssuer string = "uauth"

var tokenIssuer *string

func SetTokenIssuer(_tokenIssuer string) {
	tokenIssuer = &_tokenIssuer
}
