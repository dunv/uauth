module uauthExample

go 1.13

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/dunv/uauth v1.0.70
	github.com/dunv/uhttp v1.0.73
	github.com/dunv/ulog v1.0.23
	github.com/dunv/umongo v1.0.19 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/prometheus/client_golang v1.9.0 // indirect
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/tidwall/pretty v1.0.1 // indirect
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83 // indirect
	golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/api v0.3.1
	google.golang.org/protobuf v1.25.0 // indirect
)

replace github.com/dunv/uauth => ../

// replace github.com/dunv/umongo => ../../umongo
