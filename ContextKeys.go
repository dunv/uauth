package uauth

const (
	// These contextKeys are used only when using auth's features for user-management (auth-server, roles, etc.)
	// Context key which allows access to a mongoClient connected to the user db
	CtxKeyUserDbClient string = "uauth.ctxKeyUserDbClient"
	// Context key which allows access to the name of the used userDB
	CtxKeyUserDbName string = "uauth.ctxKeyUserDbName"
	// Context key which allows access to the BCrypt secret (for generating and verifying JWT)
	CtxKeyBCryptSecret string = "uauth.ctxKeyBCryptSecret"
	// Context key which allows access to a readily parsed and evaluated user-object
	CtxKeyUser string = "uauth.ctxKeyUser"

	// The contextKeys below are used for "all" kinds of authentication (i.e. only verifying authorization)
	// Context key which allows access to a user-object of type interface
	CtxKeyCustomUser string = "uauth.ctxKeyCustomUser"
	// Context key which makes the authentication method accessible
	CtxKeyAuthMethod string = "uauth.ctxKeyAuthMethod"
)
