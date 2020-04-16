module github.com/dunv/uauth

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.13
	github.com/dunv/uhttp v1.0.48
	github.com/dunv/ulog v1.0.18
	github.com/dunv/umongo v1.0.12
	go.mongodb.org/mongo-driver v1.3.2
	golang.org/x/crypto v0.0.0-20200414173820-0848c9571904
)

// replace github.com/dunv/uhttp => ../uhttp
// replace github.com/dunv/umongo => ../umongo
