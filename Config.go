package uauth

import (
	"time"

	"github.com/dunv/uhttp"
	"go.mongodb.org/mongo-driver/mongo"
)

type Config struct {
	// uhttp instance
	UHTTP *uhttp.UHTTP

	// Token secret used for signing and verifying tokens
	BCryptSecret string

	// Connection to the mongo-database
	UserDB                 *mongo.Client
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
