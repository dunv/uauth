module github.com/dunv/uauth

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.4
	github.com/dunv/uhttp v1.0.29
	github.com/dunv/ulog v0.0.13
	github.com/dunv/umongo v1.0.8
	go.mongodb.org/mongo-driver v1.1.1
	golang.org/x/crypto v0.0.0-20190907121410-71b5226ff739
)

// replace github.com/dunv/uhttp => ../uhttp
