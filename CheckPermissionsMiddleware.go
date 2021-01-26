package uauth

import (
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

// Check that the user has the specified permissions
func CheckPermissions(permissions ...Permission) uhttp.Middleware {
	tmp := uhttp.Middleware(func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if packageConfig.UserDbName == "" || packageConfig.UserDbConnectionString == "" || packageConfig.BCryptSecret == "" {
				ulog.Panic(fmt.Errorf("uauth packageConfig has not been set, unable to use AuthJWT() (%v)", packageConfig))
			}

			user, err := UserFromRequest(r)
			if err != nil {
				ulog.Infof("Denying access (%s)", err)
				packageConfig.UHTTP.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}

			for _, permission := range permissions {

				if !user.CheckPermission(permission) {
					packageConfig.UHTTP.RenderError(w, r, fmt.Errorf("Unauthorized: user does not have required permissions (%s)", permission))
					return
				}
			}
			next.ServeHTTP(w, r)
		}
	})
	return tmp
}
