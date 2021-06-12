module github.com/provideplatform/pgrok

go 1.16

replace github.com/provideapp/ident => ../ident

require (
	github.com/gin-gonic/gin v1.7.2 // indirect
	github.com/kthomas/go-logger v0.0.0-20210526080020-a63672d0724c
	github.com/provideapp/ident v0.0.0-00010101000000-000000000000
	github.com/provideservices/provide-go v0.0.0-20210610091141-756e6385f6b8
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
)
