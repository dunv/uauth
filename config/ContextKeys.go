package config

import contextKeys "github.com/dunv/uhttp/contextkeys"

const (
	// Context key which allows access to a mongoClient connected to the user db
	CtxKeyUserDB contextKeys.ContextKey = "uauth.ctxKeyUserDb"
	// Context key which allows access to a readily parsed and evaluated user-object
	CtxKeyUser contextKeys.ContextKey = "uauth.ctxKeyUser"
)
