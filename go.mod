module github.com/dunv/uauth

go 1.15

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/dunv/uhelpers v1.0.14
	github.com/dunv/uhttp v1.0.75
	github.com/dunv/ulog v1.0.24
	github.com/dunv/umongo v1.0.21
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/prometheus/common v0.29.0 // indirect
	github.com/prometheus/procfs v0.7.1 // indirect
	go.mongodb.org/mongo-driver v1.7.0
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

// replace github.com/dunv/uhttp => ../uhttp
// replace github.com/dunv/umongo => ../umongo
