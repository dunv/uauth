module uauthExample

go 1.13

require (
	github.com/dunv/uauth v1.0.70
	github.com/dunv/uhttp v1.0.79
	github.com/dunv/ulog v1.0.24
	github.com/prometheus/client_golang v1.11.1 // indirect
	github.com/tidwall/pretty v1.0.1 // indirect
)

replace github.com/dunv/uauth => ../

// replace github.com/dunv/umongo => ../../umongo
