module github.com/dunv/uauth

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.11
	github.com/dunv/uhttp v1.0.43
	github.com/dunv/ulog v1.0.8
	github.com/dunv/umongo v1.0.8
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	go.mongodb.org/mongo-driver v1.1.1
	golang.org/x/crypto v0.0.0-20190907121410-71b5226ff739
)

// replace github.com/dunv/uhttp => ../uhttp
