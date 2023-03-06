module github.com/dunv/uauth

go 1.15

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.14
	github.com/dunv/uhttp v1.0.79
	github.com/dunv/ulog v1.0.24
	github.com/dunv/umongo v1.0.21
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/klauspost/compress v1.13.5 // indirect
	go.mongodb.org/mongo-driver v1.7.1
	golang.org/x/crypto v0.1.0
)

// replace github.com/dunv/uhttp => ../uhttp
// replace github.com/dunv/umongo => ../umongo
