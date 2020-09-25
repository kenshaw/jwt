// _example/main.go
package main

//go:generate openssl genrsa -out rsa-private.pem 2048
//go:generate openssl rsa -in rsa-private.pem -outform PEM -pubout -out rsa-public.pem

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"time"

	"github.com/kenshaw/jwt"
	"github.com/kenshaw/pemutil"
)

func main() {
	var err error

	// load key
	keyset, err := pemutil.LoadFile("rsa-private.pem")
	if err != nil {
		log.Fatal(err)
	}

	// create PS384 using keyset
	// in addition, there are the other standard JWT encryption implementations:
	// HMAC:         HS256, HS384, HS512
	// RSA-PKCS1v15: RS256, RS384, RS512
	// ECC:          ES256, ES384, ES512
	// RSA-SSA-PSS:  PS256, PS384, PS512
	ps384, err := jwt.PS384.New(keyset)
	if err != nil {
		log.Fatal(err)
	}

	// calculate an expiration time
	expr := time.Now().Add(14 * 24 * time.Hour)

	// create claims using provided jwt.Claims
	c0 := jwt.Claims{
		Issuer:     "user@example.com",
		Audience:   "client@example.com",
		Expiration: json.Number(strconv.FormatInt(expr.Unix(), 10)),
	}
	fmt.Printf("Claims: %+v\n\n", c0)

	// encode token
	buf, err := ps384.Encode(&c0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encoded token:\n\n%s\n\n", string(buf))

	// decode the generated token and verify
	c1 := jwt.Claims{}
	err = ps384.Decode(buf, &c1)
	if err != nil {
		// if the signature was bad, the err would not be nil
		log.Fatal(err)
	}
	if reflect.DeepEqual(c0, c1) {
		fmt.Printf("Claims Match! Decoded claims: %+v\n\n", c1)
	}

	fmt.Println("----------------------------------------------")

	// use custom claims
	c3 := map[string]interface{}{
		"aud":                      "my audience",
		"http://example/api/write": true,
	}
	fmt.Printf("My Custom Claims: %+v\n\n", c3)

	buf, err = ps384.Encode(&c3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Encoded token with custom claims:\n\n%s\n\n", string(buf))

	// decode custom claims
	c4 := myClaims{}
	err = ps384.Decode(buf, &c4)
	if err != nil {
		log.Fatal(err)
	}
	if c4.Audience == "my audience" {
		fmt.Printf("Decoded custom claims: %+v\n\n", c1)
	}
	if c4.WriteScope {
		fmt.Println("myClaims custom claims has write scope!")
	}
}

// or use any type that the standard encoding/json library recognizes as a
// payload (you can also "extend" jwt.Claims in this fashion):
type myClaims struct {
	jwt.Claims
	WriteScope bool `json:"http://example/api/write"`
}
