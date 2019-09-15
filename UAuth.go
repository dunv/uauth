package uauth

import (
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
	"github.com/dunv/ulog"
	"go.mongodb.org/mongo-driver/mongo"
)

var packageConfig config.Config

func SetConfig(_config config.Config) {
	packageConfig = _config
	models.AdditionalAttributesModel = _config.AdditionalUserAttributes
}

func Config() config.Config {
	return packageConfig
}

func User(r *http.Request) models.User {
	if user, ok := r.Context().Value(config.CtxKeyUser).(models.User); ok {
		return user
	}
	ulog.Errorf("could not find user in request context. Did you specify AuthRequired in handler config?")
	return models.User{}
}

func UserDB(r *http.Request) *mongo.Client {
	if user, ok := r.Context().Value(config.CtxKeyUserDB).(*mongo.Client); ok {
		return user
	}
	ulog.Errorf("could not find userDB in request context. Did you specify AuthRequired in handler config?")
	return nil
}
