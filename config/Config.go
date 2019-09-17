package config

import (
	"github.com/dunv/uauth/interfaces"
	"go.mongodb.org/mongo-driver/mongo"
)

type Config struct {
	BCryptSecret             string
	UserDbClient             *mongo.Client
	UserDbName               string
	TokenIssuer              string
	AdditionalUserAttributes interfaces.AdditionalUserAttributesInterface
}
