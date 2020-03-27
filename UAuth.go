package uauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
	"github.com/dunv/umongo"
	"go.mongodb.org/mongo-driver/mongo"
)

// TODO: protect methods which can only be used if config has been initialized
// TODO: expose authGet, Basic, JWT with custom usermodels as "helpers"
// TODO: add logging lib-config

var packageConfig Config

func SetConfig(_config Config) error {
	packageConfig = _config
	AdditionalAttributesModel = _config.AdditionalUserAttributes

	mongoClient, _, err := umongo.NewDbClient(_config.UserDbConnectionString, time.Second)
	if err != nil {
		return fmt.Errorf("Could not connect to db. Exiting (%v)", err)
	}

	uhttp.AddContext(CtxKeyUserDbClient, mongoClient)
	uhttp.AddContext(CtxKeyConfig, _config)
	uhttp.AddContext(CtxKeyUserDbName, _config.UserDbName)

	if err := CreateInitialRolesIfNotExist(mongoClient, _config.UserDbName); err != nil {
		return err
	}

	if err := CreateInitialUsersIfNotExist(mongoClient, _config.UserDbName); err != nil {
		return err
	}

	if len(_config.WantedRoles) > 0 {
		err := CreateCustomRolesIfNotExist(mongoClient, _config.UserDbName, _config.WantedRoles, _config.TokenIssuer)
		if err != nil {
			return err
		}
	}

	return nil
}

func UserFromRequest(r *http.Request) User {
	if user, ok := r.Context().Value(CtxKeyUser).(User); ok {
		return user
	}
	ulog.Errorf("could not find user in request context")
	return User{}
}

func GenericUserFromRequest(r *http.Request) interface{} {
	return r.Context().Value(CtxKeyUser)
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

func ConfigFromRequest(r *http.Request) Config {
	if r.Context().Value(CtxKeyConfig) != nil {
		return r.Context().Value(CtxKeyConfig).(Config)
	}
	ulog.Panic("could not find config in request context")
	// this will never be reached
	return Config{}
}
