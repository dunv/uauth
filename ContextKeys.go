package uauth

import "github.com/dunv/uhttp"

const (
	// Context key which allows access to a mongoClient connected to the user db
	CtxKeyUserDbClient uhttp.ContextKey = "uauth.ctxKeyUserDbClient"

	// Context key which allows access to the name of the used userDB
	CtxKeyUserDbName uhttp.ContextKey = "uauth.ctxKeyUserDbName"

	// Context key which allows access to the BCrypt secret (for generating and verifying JWT)
	CtxKeyUser uhttp.ContextKey = "uauth.ctxKeyUser"

	// Context key which allows access to a readily parsed and evaluated user-object
	CtxKeyConfig uhttp.ContextKey = "uauth.ctxKeyConfig"

	// Context key which makes the authentication method accessible
	CtxKeyAuthMethod uhttp.ContextKey = "uauth.ctxKeyAuthMethod"
)
