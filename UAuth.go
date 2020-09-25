package uauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dunv/ulog"
	"github.com/dunv/umongo"
	"go.mongodb.org/mongo-driver/mongo"
)

// TODO: add logging lib-config

var packageConfig Config

func SetConfig(_config Config) error {
	packageConfig = _config

	if packageConfig.UHTTP == nil {
		return errors.New("UHTTP needs to be set in config")
	}

	mongoClient, _, err := umongo.NewDbClient(_config.UserDbConnectionString, fmt.Sprintf("uauth_%s", _config.TokenIssuer), time.Second)
	if err != nil {
		return fmt.Errorf("Could not connect to db. Exiting (%v)", err)
	}

	if err := packageConfig.UHTTP.AddContext(CtxKeyUserDbClient, mongoClient); err != nil {
		return err
	}

	if err := packageConfig.UHTTP.AddContext(CtxKeyConfig, &_config); err != nil {
		return err
	}

	if err := packageConfig.UHTTP.AddContext(CtxKeyUserDbName, _config.UserDbName); err != nil {
		return err
	}

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

func UserFromContext(ctx context.Context, additionalAttributes ...interface{}) (*User, error) {
	var user User
	var ok bool
	if user, ok = ctx.Value(CtxKeyUser).(User); !ok {
		return nil, errors.New("could not find user in request context")
	}

	if len(additionalAttributes) == 1 && additionalAttributes[0] != nil {
		bytes, err := json.Marshal(user.AdditionalAttributes)
		if err != nil {
			return nil, fmt.Errorf("could not marshal additionalAttributes (%s)", err)
		}

		err = json.Unmarshal(bytes, additionalAttributes[0])
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal additionalAttributes (%s)", err)
		}
	}

	return &user, nil

}

func UserFromRequest(r *http.Request, additionalAttributes ...interface{}) (*User, error) {
	return UserFromContext(r.Context(), additionalAttributes...)
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

func ConfigFromRequest(r *http.Request) (*Config, error) {
	return ConfigFromContext(r.Context())
}

func ConfigFromContext(ctx context.Context) (*Config, error) {
	if ctx.Value(CtxKeyConfig) != nil {
		return ctx.Value(CtxKeyConfig).(*Config), nil
	}
	return nil, errors.New("could not find config in request context")
}
