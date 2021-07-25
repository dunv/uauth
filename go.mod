module github.com/dunv/uauth

go 1.15

require (
	github.com/aws/aws-sdk-go v1.37.30 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.14
	github.com/dunv/uhttp v1.0.75
	github.com/dunv/ulog v1.0.23
	github.com/dunv/umongo v1.0.19
	github.com/golang/snappy v0.0.3 // indirect
	github.com/klauspost/compress v1.11.12 // indirect
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a // indirect
	go.mongodb.org/mongo-driver v1.5.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20210313202042-bd2e13477e9c // indirect
	golang.org/x/text v0.3.5 // indirect
)

// replace github.com/dunv/uhttp => ../uhttp
// replace github.com/dunv/umongo => ../umongo
