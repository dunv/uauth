package uauth

import (
	"time"

	"github.com/dunv/uhttp"
)

type Config struct {
	// uhttp instance
	UHTTP *uhttp.UHTTP

	// Token secret used for signing and verifying tokens
	BCryptSecret string

	// Connection to the mongo-database
	UserDbConnectionString string
	UserDbName             string

	// Name of the token issue when tokens are created
	TokenIssuer string

	// Which roles should the package create for you
	WantedRoles []Role

	// How long will the refreshToken be valid
	RefreshTokenValidity time.Duration

	// How long will the accessToken be valid
	AccessTokenValidity time.Duration
}
