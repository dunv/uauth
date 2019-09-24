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

// TODO: protect methods which can only be used if config has been initialized
// TODO: expose authGet, Basic, JWT with custom usermodels as "helpers"
// TODO: add logging lib-config

var packageConfig config.Config

func SetConfig(_config config.Config) error {
	packageConfig = _config
	models.AdditionalAttributesModel = _config.AdditionalUserAttributes

	uhttp.AddContext(CtxKeyUserDbClient, _config.UserDbClient)
	uhttp.AddContext(CtxKeyUserDbName, _config.UserDbName)
	uhttp.AddContext(CtxKeyBCryptSecret, _config.BCryptSecret)

	if err := services.CreateInitialRolesIfNotExist(_config.UserDbClient, _config.UserDbName); err != nil {
		return err
	}

	if err := services.CreateInitialUsersIfNotExist(_config.UserDbClient, _config.UserDbName); err != nil {
		return err
	}

	if len(_config.WantedRoles) > 0 {
		err := services.CreateCustomRolesIfNotExist(_config.UserDbClient, _config.UserDbName, _config.WantedRoles, _config.TokenIssuer)
		if err != nil {
			return err
		}
	}

	return nil
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

func CustomUser(r *http.Request) interface{} {
	if r.Context().Value(CtxKeyCustomUser) != nil {
		return r.Context().Value(CtxKeyCustomUser)
	}
	ulog.Errorf("could not find customUser in request context")
	return nil
}

func IsAuthBasic(r *http.Request) bool {
	return IsAuthMethod("basic", r)
}

func IsAuthJWT(r *http.Request) bool {
	return IsAuthMethod("jwt", r)
}

func IsAuthMethod(authMethod string, r *http.Request) bool {
	if r.Context().Value(CtxKeyAuthMethod) != nil && r.Context().Value(CtxKeyAuthMethod) == authMethod {
		return true
	}
	return false
}
