package uauth

import (
	"time"
)

type Config struct {
	// Token secret used for signing and verifying tokens
	BCryptSecret string

	// Connection to the mongo-database
	UserDbConnectionString string
	UserDbName             string

	// Name of the token issue when tokens are created
	TokenIssuer string

	// These attributes can be saved and retrieved in the user document
	AdditionalUserAttributes AdditionalUserAttributesInterface

	// Which roles should the package create for you
	WantedRoles []Role

	// How long will the refreshToken be valid
	RefreshTokenValidity time.Duration

	// How long will the accessToken be valid
	AccessTokenValidity time.Duration
}
