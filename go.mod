module github.com/dunv/uauth

go 1.12

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhttp v1.0.28
	github.com/dunv/ulog v0.0.10
	github.com/dunv/umongo v1.0.8
	github.com/sirupsen/logrus v1.4.2
	go.mongodb.org/mongo-driver v1.1.1
	golang.org/x/crypto v0.0.0-20190907121410-71b5226ff739
)

replace github.com/dunv/uhttp => ../uhttp
