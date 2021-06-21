module github.com/provideplatform/pgrok

go 1.16

replace github.com/provideapp/ident => ../ident

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/kthomas/go-logger v0.0.0-20210526080020-a63672d0724c
	github.com/kthomas/go-self-signed-cert v0.0.0-20200602041729-f9878375d46e
	github.com/provideservices/provide-go v0.0.0-20210614032206-f6699b1760e1
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
)
