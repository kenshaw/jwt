package jwt

//go:generate stringer -type Algorithm -output alg_string.go alg.go

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"strconv"

	"github.com/knq/pemutil"
)

// Algorithm is the type for signing algorithms implemented in the package.
type Algorithm uint

// Signer is the shared interface for a signature.
type Signer interface {
	// Sign creates a signature for buf, storing it as a base64 safe string in
	// dst.
	Sign(buf []byte) ([]byte, error)

	// Verify creates a signature for buf, and compares it against the base64
	// encoded sig, returning any errors or ErrInvalidSignature if they do not
	// match, or the b64 decoded signature if the signature is valid.
	Verify(buf, sig []byte) ([]byte, error)
}

// PEM is the wrapper around passed keys.
type PEM pemutil.PEM

const (
	// NONE provides a JWT signing method for NONE. This is not implemented for security
	// reasons.
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

// algMap is the actual algorithm implementations
var algMap = map[Algorithm]struct {
	NewFunc func(PEM, crypto.Hash) Signer
	Hash    crypto.Hash
}{
	// none
	NONE: {func(PEM, crypto.Hash) Signer {
		panic("not implemented")
		return nil
	}, crypto.SHA256},

	// HS256 is HMAC + SHA-256
	HS256: {NewHMACSigner, crypto.SHA256},

	// HS384 is HMAC + SHA-384
	HS384: {NewHMACSigner, crypto.SHA384},

	// HS512 is HMAC + SHA-512
	HS512: {NewHMACSigner, crypto.SHA512},

	// RS256 is RSASSA-PKCS1-V1_5 + SHA-256
	RS256: {NewRSASigner(PKCS1v15RSAMethod), crypto.SHA256},

	// RS384 is RSASSA-PKCS1-V1_5 + SHA-384
	RS384: {NewRSASigner(PKCS1v15RSAMethod), crypto.SHA384},

	// RS512 is RSASSA-PKCS1-V1_5 + SHA-512
	RS512: {NewRSASigner(PKCS1v15RSAMethod), crypto.SHA512},

	// ES256 is ECDSA P-256 + SHA-256
	ES256: {NewEllipticSigner(elliptic.P256()), crypto.SHA256},

	// ES384 is ECDSA P-384 + SHA-384
	ES384: {NewEllipticSigner(elliptic.P384()), crypto.SHA384},

	// ES512 is ECDSA P-521 + SHA-512
	ES512: {NewEllipticSigner(elliptic.P521()), crypto.SHA512},

	// PS256 is RSASSA-PSS + SHA-256
	PS256: {NewRSASigner(PSSRSAMethod), crypto.SHA256},

	// PS384 is RSASSA-PSS + SHA-384
	PS384: {NewRSASigner(PSSRSAMethod), crypto.SHA384},

	// PS512 is RSASSA-PSS + SHA-512
	PS512: {NewRSASigner(PSSRSAMethod), crypto.SHA512},
}

// New instantiates a new instance of a JWT encoder/decoder using the supplied
// key.
func (alg Algorithm) New(key PEM) Signer {
	a := algMap[alg]

	// check hash
	if !a.Hash.Available() {
		panic("hash unavailable")
		return nil
	}

	return a.NewFunc(key, a.Hash)
}

// Header builds the JWT header for the algorithm.
func (alg Algorithm) Header() Header {
	return Header{
		Type:      "JWT",
		Algorithm: alg,
	}
}

// Encode encodes a JWT using the supplied key with the Algorithm.
func (alg Algorithm) Encode(key PEM, obj interface{}) ([]byte, error) {
	return Encode(alg, alg.New(key), obj)
}

// Decode verifies the signature of a Token against the Algorithm, decoding any
// data in buf to the token.
func (alg Algorithm) Decode(key PEM, buf []byte, obj interface{}) error {
	return Decode(alg, alg.New(key), buf, obj)
}

// MarshalJSON marshals Algorithm into a storable JSON string.
func (alg *Algorithm) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(alg.String())), nil
}

// UnmarshalJSON unmarshals the a JSON string into the corresponding Algorithm.
func (alg *Algorithm) UnmarshalJSON(buf []byte) error {
	// unquote string ...
	val, err := strconv.Unquote(string(buf))
	if err != nil {
		return err
	}

	switch val {
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
