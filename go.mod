module github.com/dunv/uauth

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.12
	github.com/dunv/uhttp v1.0.48
	github.com/dunv/ulog v1.0.18
	github.com/dunv/umongo v1.0.10
	go.mongodb.org/mongo-driver v1.3.1
	golang.org/x/crypto v0.0.0-20191002192127-34f69633bfdc
)

// replace github.com/dunv/uhttp => ../uhttp
