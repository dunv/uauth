package uauth

const (
	// Context key which allows access to a mongoClient connected to the user db
	CtxKeyUserDbClient string = "uauth.ctxKeyUserDbClient"
	// Context key which allows access to the name of the used userDB
	CtxKeyUserDbName string = "uauth.ctxKeyUserDbName"
	// Context key which allows access to a readily parsed and evaluated user-object
	CtxKeyUser string = "uauth.ctxKeyUser"
	// Context key which allows access to the BCrypt secret (for generating and verifying JWT)
	CtxKeyBCryptSecret string = "uauth.ctxKeyBCryptSecret"
	// Context key which makes the authentication method accessible
	CtxKeyAuthMethod string = "uauth.ctxKeyAuthMethod"
)
