package handlers

import (
	"github.com/dunv/uhttp"
)

func CreateDefaultHandlers() {
	// Login with username and password
	uhttp.Handle("/uauth/login", LoginHandler)

	// RefreshToken (accessible by every user)
	uhttp.Handle("/uauth/accessTokenFromRefreshToken", AccessTokenFromRefreshTokenHandler) // Get access-token by supplying a valid refresh-token
	uhttp.Handle("/uauth/renewRefreshToken", RenewRefreshTokenHandler)                     // Get a new refresh-token by supplying an old still valid one
	uhttp.Handle("/uauth/listRefreshTokens", ListRefreshTokensHandler)
	uhttp.Handle("/uauth/deleteRefreshToken", DeleteRefreshTokenHandler)

	// Check if login works
	uhttp.Handle("/uauth/checkLogin", CheckLoginHandler)

	// Admin handlers
	uhttp.Handle("/uauth/getUser", GetUserHandler)
	uhttp.Handle("/uauth/listUsers", ListUsersHandler)
	uhttp.Handle("/uauth/listRoles", ListRolesHandler)
	uhttp.Handle("/uauth/createUser", CreateUserHandler)
	uhttp.Handle("/uauth/updateUser", UpdateUserHandler)
	uhttp.Handle("/uauth/deleteUser", DeleteUserHandler)
}
