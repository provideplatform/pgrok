module github.com/provideplatform/pgrok

go 1.16

replace github.com/provideplatform/ident => ../ident

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/kthomas/go-logger v0.0.0-20210526080020-a63672d0724c
	github.com/kthomas/go-redisutil v0.0.0-20210621163534-1f741c230b1f
	github.com/kthomas/go-self-signed-cert v0.0.0-20200602041729-f9878375d46e
	github.com/provideplatform/provide-go v0.0.0-20210624064849-d7328258f0d8
	golang.org/x/crypto v0.1.0
)
