package helpers

import "github.com/dunv/uauth/permissions"

func PtrToPermission(p permissions.Permission) *permissions.Permission {
	return &p
}
