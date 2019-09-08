package config

import "github.com/dunv/uhttp"

const (
	// Context key which allows access to a mongoClient connected to the user db
	CtxKeyUserDB uhttp.ContextKey = "uauth.ctxKeyUserDb"
	// Context key which allows access to a readily parsed and evaluated user-object
	CtxKeyUser uhttp.ContextKey = "uauth.ctxKeyUser"
)
