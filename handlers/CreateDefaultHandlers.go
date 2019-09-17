package handlers

import "github.com/dunv/uhttp"

func CreateDefaultHandlers() {
	uhttp.Handle("/api/login", LoginHandler)
	uhttp.Handle("/api/checkLogin", CheckLoginHandler)
	uhttp.Handle("/api/getUser", GetUserHandler)
	uhttp.Handle("/api/listUsers", ListUsersHandler)
	uhttp.Handle("/api/listRoles", ListRolesHandler)
	uhttp.Handle("/api/createUser", CreateUserHandler)
	uhttp.Handle("/api/updateUser", UpdateUserHandler)
	uhttp.Handle("/api/deleteUser", DeleteUserHandler)
}
