package uauth

import (
	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
)

var packageConfig config.Config

func SetConfig(_config config.Config) {
	packageConfig = _config
	models.AdditionalAttributesModel = _config.AdditionalUserAttributes
}

func Config() config.Config {
	return packageConfig
}
