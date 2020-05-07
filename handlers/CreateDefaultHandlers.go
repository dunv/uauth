package handlers

import (
	"github.com/dunv/uhttp"
)

func CreateDefaultHandlers(u *uhttp.UHTTP) {
	// Login with username and password
	u.Handle("/uauth/login", LoginHandler)

	// RefreshToken (accessible by every user)
	u.Handle("/uauth/accessTokenFromRefreshToken", AccessTokenFromRefreshTokenHandler) // Get access-token by supplying a valid refresh-token
	u.Handle("/uauth/renewRefreshToken", RenewRefreshTokenHandler)                     // Get a new refresh-token by supplying an old still valid one
	u.Handle("/uauth/listRefreshTokens", ListRefreshTokensHandler)
	u.Handle("/uauth/deleteRefreshToken", DeleteRefreshTokenHandler)

	// Check if login works
	u.Handle("/uauth/checkLogin", CheckLoginHandler)

	// Admin handlers
	u.Handle("/uauth/getUser", GetUserHandler)
	u.Handle("/uauth/listUsers", ListUsersHandler)
	u.Handle("/uauth/listRoles", ListRolesHandler)
	u.Handle("/uauth/createUser", CreateUserHandler)
	u.Handle("/uauth/updateUser", UpdateUserHandler)
	u.Handle("/uauth/deleteUser", DeleteUserHandler)
}
