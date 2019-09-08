package config

import "github.com/dunv/uauth/interfaces"

type Config struct {
	UserDbName               string
	TokenIssuer              string
	AdditionalUserAttributes interfaces.AdditionalUserAttributesInterface
}
