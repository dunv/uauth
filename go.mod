module github.com/dunv/uauth

go 1.15

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.13
	github.com/dunv/uhttp v1.0.65
	github.com/dunv/ulog v1.0.21
	github.com/dunv/umongo v1.0.17
	go.mongodb.org/mongo-driver v1.4.1
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
)

// replace github.com/dunv/uhttp => ../uhttp
// replace github.com/dunv/umongo => ../umongo
