package config

import uhttpModels "github.com/dunv/uhttp/models"

const (
	// Context key which allows access to a mongoClient connected to the user db
	CtxKeyUserDB uhttpModels.ContextKey = "uauth.ctxKeyUserDb"
	// Context key which allows access to a readily parsed and evaluated user-object
	CtxKeyUser uhttpModels.ContextKey = "uauth.ctxKeyUser"
)
