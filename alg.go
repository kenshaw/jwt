package jwt

//go:generate stringer -type Algorithm -output alg_string.go alg.go

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/knq/pemutil"
)

// Algorithm is the type for signing algorithms implemented in this package.
type Algorithm uint

// Signer is the shared interface for an Algorithm's encoding, decoding,
// signing, and verify to handle the crypto primitives and lower-level API
// calls.
type Signer interface {
	// Sign creates a signature for buf, returning it as a URL-safe base64
	// encoded byte slice.
	Sign(buf []byte) ([]byte, error)

	// Verify creates a signature for buf, comparing it against the URL-safe
	// base64 encoded sig. If the sig is invalid, then ErrInvalidSignature will
	// be returned.
	Verify(buf, sig []byte) ([]byte, error)

	// Encode encodes obj as a token.
	Encode(obj interface{}) ([]byte, error)

	// Decode decodes a serialized token, verifying the signature, storing the
	// decoded data from the token in obj.
	Decode(buf []byte, obj interface{}) error
}

// PEM is a wrapper that assists with loading PEM-encoded crypto primitives
// (ie, rsa.PrivateKey, ecdsa.PrivateKey, etc).
type PEM pemutil.PEM

const (
	// NONE provides a JWT signing method for NONE.
	//
	// NOTE: This is not implemented for security reasons.
	NONE Algorithm = iota

	// HS256 provides a JWT signing method for HMAC using SHA-256.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.2
	HS256

	// HS384 provides a JWT signing method for HMAC using SHA-384.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.2
	HS384

	// HS512 provides a JWT signing method for HMAC using SHA-512.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.2
	HS512

	// RS256 provides a JWT signing method for RSASSA-PKCS1-V1_5 using SHA-256.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.3
	RS256

	// RS384 provides a JWT signing method for RSASSA-PKCS1-V1_5 using SHA-384.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.3
	RS384

	// RS512 provides a JWT signing method for RSASSA-PKCS1-V1_5 using SHA-512.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.3
	RS512

	// ES256 provides a JWT signing method for ECDSA using P-256 and SHA-256.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.4
	ES256

	// ES384 provides a JWT signing method for ECDSA using P-384 and SHA-384.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.4
	ES384

	// ES512 provides a JWT signing method for ECDSA using P-521 and SHA-512.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.4
	ES512

	// PS256 provides a JWT signing method for RSASSA-PSS using SHA-256 and
	// MGF1 mask generation function with SHA-256.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.5
	PS256

	// PS384 provides a JWT signing method for RSASSA-PSS using SHA-384 hash
	// algorithm and MGF1 mask generation function with SHA-384.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.5
	PS384

	// PS512 provides a JWT signing method for RSASSA-PSS using SHA-512 hash
	// algorithm and MGF1 mask generation function with SHA-512.
	//
	// See http://tools.ietf.org/html/rfc7518#section-3.5
	PS512
)

// algMap is a map of algorithm implementations to its Algorithm.
var algMap = map[Algorithm]struct {
	NewFunc func(pemutil.Store, crypto.Hash) Signer
	Hash    crypto.Hash
}{
	// none
	NONE: {func(pemutil.Store, crypto.Hash) Signer {
		panic("not implemented")
		return nil
	}, crypto.SHA256},

	// HS256 is HMAC + SHA-256
	HS256: {NewHMACSigner(HS256), crypto.SHA256},

	// HS384 is HMAC + SHA-384
	HS384: {NewHMACSigner(HS384), crypto.SHA384},

	// HS512 is HMAC + SHA-512
	HS512: {NewHMACSigner(HS512), crypto.SHA512},

	// RS256 is RSASSA-PKCS1-V1_5 + SHA-256
	RS256: {NewRSASigner(RS256, PKCS1v15RSAMethod), crypto.SHA256},

	// RS384 is RSASSA-PKCS1-V1_5 + SHA-384
	RS384: {NewRSASigner(RS384, PKCS1v15RSAMethod), crypto.SHA384},

	// RS512 is RSASSA-PKCS1-V1_5 + SHA-512
	RS512: {NewRSASigner(RS512, PKCS1v15RSAMethod), crypto.SHA512},

	// ES256 is ECDSA P-256 + SHA-256
	ES256: {NewEllipticSigner(ES256, elliptic.P256()), crypto.SHA256},

	// ES384 is ECDSA P-384 + SHA-384
	ES384: {NewEllipticSigner(ES384, elliptic.P384()), crypto.SHA384},

	// ES512 is ECDSA P-521 + SHA-512
	ES512: {NewEllipticSigner(ES512, elliptic.P521()), crypto.SHA512},

	// PS256 is RSASSA-PSS + SHA-256
	PS256: {NewRSASigner(PS256, PSSRSAMethod), crypto.SHA256},

	// PS384 is RSASSA-PSS + SHA-384
	PS384: {NewRSASigner(PS384, PSSRSAMethod), crypto.SHA384},

	// PS512 is RSASSA-PSS + SHA-512
	PS512: {NewRSASigner(PS512, PSSRSAMethod), crypto.SHA512},
}

// New creates a Signer using the supplied keyset.
//
// The keyset can be of type PEM, pemutil.PEM, pemutil.Store,
// *rsa.{PrivateKey,PublicKey}, *ecdsa.{PrivateKey,PublicKey}, or []byte.
//
// PLEASE NOTE: if a calling package *DOES NOT* provide a private key, tokens
// cannot be Encode'd. Similarly, if no public key is provided, tokens *CANNOT*
// be Decode'd (ie, verified). Additionally, as this is a naive implementation,
// no attempt is made to generate or derive a public key from a private key.
// Therefore, please pass *BOTH* a public *AND* private key (if the Algorithm
// calls for it), wrapped by a pemutil.Store or as PEM/pemutil.PEM in order to
// Encode *AND* Decode JWTs.
//
// New will panic if the provided keyset does not provide enough information,
// or the keyset data cannot be loaded, is invalid, is otherwise incorrect for
// the Algorithm, or if the associated crypto.Hash (ie, SHA256, SHA384, or
// SHA512) is not available for the platform.
func (alg Algorithm) New(keyset interface{}) Signer {
	a := algMap[alg]

	// check hash
	if !a.Hash.Available() {
		panic(fmt.Sprintf("%s.New: crypto hash unavailable", alg))
		return nil
	}

	var store pemutil.Store

	// load the data
	switch p := keyset.(type) {
	case pemutil.Store:
		store = p

	// pem data
	case pemutil.PEM:
		store = loadKeysFromPEM(p)
	case PEM:
		store = loadKeysFromPEM(pemutil.PEM(p))

	// raw key
	case []byte:
		store = pemutil.Store{pemutil.PrivateKey: p}

	// rsa keys
	case *rsa.PrivateKey:
		store = pemutil.Store{pemutil.RSAPrivateKey: p}
	case *rsa.PublicKey:
		store = pemutil.Store{pemutil.PublicKey: p}

	// ecc keys
	case *ecdsa.PrivateKey:
		store = pemutil.Store{pemutil.ECPrivateKey: p}
	case *ecdsa.PublicKey:
		store = pemutil.Store{pemutil.PublicKey: p}

	default:
		panic(fmt.Sprintf("%s.New: unrecognized keyset type", alg))
		return nil
	}

	return a.NewFunc(store, a.Hash)
}

// Header builds the JWT header for the algorithm.
func (alg Algorithm) Header() Header {
	return Header{
		Type:      "JWT",
		Algorithm: alg,
	}
}

// Encode encodes a JWT using the Algorithm and Signer.
func (alg Algorithm) Encode(signer Signer, obj interface{}) ([]byte, error) {
	return Encode(alg, signer, obj)
}

// Decode verifies the signature of a JWT against the Algorithm, decoding any
// data in buf to obj.
func (alg Algorithm) Decode(signer Signer, buf []byte, obj interface{}) error {
	return Decode(alg, signer, buf, obj)
}

// MarshalText marshals Algorithm into a standard string.
func (alg Algorithm) MarshalText() ([]byte, error) {
	return []byte(alg.String()), nil
}

// UnmarshalText unmarshals a string into the corresponding Algorithm.
func (alg *Algorithm) UnmarshalText(buf []byte) error {
	switch string(buf) {
	// hmac
	case "HS256":
		*alg = HS256
	case "HS384":
		*alg = HS384
	case "HS512":
		*alg = HS512

	// rsa-pkcs1v15
	case "RS256":
		*alg = RS256
	case "RS384":
		*alg = RS384
	case "RS512":
		*alg = RS512

	// ecc
	case "ES256":
		*alg = ES256
	case "ES384":
		*alg = ES384
	case "ES512":
		*alg = ES512

	// rsa-pss
	case "PS256":
		*alg = PS256
	case "PS384":
		*alg = PS384
	case "PS512":
		*alg = PS512

	// errors
	case "none":
		return errors.New("algorithm none not supported")
	default:
		return errors.New("algorithm not supported")
	}

	return nil
}
