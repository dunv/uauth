package uauth

import (
	"net/http"

	"github.com/dunv/uauth/config"
	"github.com/dunv/uauth/models"
	"github.com/dunv/uauth/services"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
	"go.mongodb.org/mongo-driver/mongo"
)

var packageConfig config.Config

func SetConfig(_config config.Config) {
	packageConfig = _config
	models.AdditionalAttributesModel = _config.AdditionalUserAttributes

	uhttp.AddContext(CtxKeyUserDbClient, _config.UserDbClient)
	uhttp.AddContext(CtxKeyUserDbName, _config.UserDbName)
	uhttp.AddContext(CtxKeyBCryptSecret, _config.BCryptSecret)

	services.CreateInitialRolesIfNotExist(_config.UserDbClient, _config.UserDbName)
	services.CreateInitialUsersIfNotExist(_config.UserDbClient, _config.UserDbName)
}

func Config() config.Config {
	return packageConfig
}

func User(r *http.Request) models.User {
	if user, ok := r.Context().Value(CtxKeyUser).(models.User); ok {
		return user
	}
	ulog.Errorf("could not find user in request context")
	return models.User{}
}

func UserDB(r *http.Request) *mongo.Client {
	if user, ok := r.Context().Value(CtxKeyUserDbClient).(*mongo.Client); ok {
		return user
	}
	ulog.Errorf("could not find userDB in request context")
	return nil
}

func UserDBName(r *http.Request) string {
	if userDbName, ok := r.Context().Value(CtxKeyUserDbName).(string); ok {
		return userDbName
	}
	ulog.Errorf("could not find userDbName in request context")
	return ""
}

func BCryptSecret(r *http.Request) string {
	if bCryptSecret, ok := r.Context().Value(CtxKeyBCryptSecret).(string); ok {
		return bCryptSecret
	}
	ulog.Errorf("could not find userDbName in request context")
	return ""
}
