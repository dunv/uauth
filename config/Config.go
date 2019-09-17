package config

import (
	"github.com/dunv/uauth/interfaces"
	"github.com/dunv/uauth/models"
	"go.mongodb.org/mongo-driver/mongo"
)

type Config struct {
	BCryptSecret             string
	UserDbClient             *mongo.Client
	UserDbName               string
	TokenIssuer              string
	AdditionalUserAttributes interfaces.AdditionalUserAttributesInterface
	WantedRoles              []models.Role
}
