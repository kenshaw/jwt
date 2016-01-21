package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"

	"github.com/knq/pemutil"
)

// rsaMethod provides a wrapper for rsa signing methods.
type rsaMethod struct {
	Sign   func(io.Reader, *rsa.PrivateKey, crypto.Hash, []byte) ([]byte, error)
	Verify func(*rsa.PublicKey, crypto.Hash, []byte, []byte) error
}

// PKCS1v15RSAMethod provides a RSA method that signs and verifies with
// PKCS1v15.
var PKCS1v15RSAMethod = rsaMethod{
	Sign:   rsa.SignPKCS1v15,
	Verify: rsa.VerifyPKCS1v15,
}

// PSSRSAMethod provides a RSA method that signs and verifies with PSS.
var PSSRSAMethod = rsaMethod{
	Sign: func(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
		return rsa.SignPSS(rand, priv, hash, hashed, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		})
	},
	Verify: func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
		return rsa.VerifyPSS(pub, hash, hashed, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		})
	},
}

// rsaSigner provides a RSA Signer.
type rsaSigner struct {
	alg    Algorithm
	method rsaMethod
	hash   crypto.Hash
	priv   *rsa.PrivateKey
	pub    *rsa.PublicKey
}

// NewRSASigner creates an RSA Signer for the specified Algorithm and RSA
// method.
func NewRSASigner(alg Algorithm, method rsaMethod) func(PEM, crypto.Hash) Signer {
	return func(pem PEM, hash crypto.Hash) Signer {
		store := loadKeysFromPEM(pem)

		var ok bool
		var privRaw, pubRaw interface{}
		var priv *rsa.PrivateKey
		var pub *rsa.PublicKey

		if privRaw, ok = store[pemutil.RSAPrivateKey]; ok {
			if priv, ok = privRaw.(*rsa.PrivateKey); !ok {
				panic("private key supplied to NewRSASigner must be *rsa.PrivateKey")
			}
		}

		if pubRaw, ok = store[pemutil.PublicKey]; ok {
			if pub, ok = pubRaw.(*rsa.PublicKey); !ok {
				panic("public key supplied to NewRSASigner must be *rsa.PublicKey")
			}
		}

		return &rsaSigner{
			alg:    alg,
			hash:   hash,
			method: method,
			priv:   priv,
			pub:    pub,
		}
	}
}

// Sign creates a signature for buf, returning it as a URL-safe base64 encoded
// byte slice.
func (rs *rsaSigner) Sign(buf []byte) ([]byte, error) {
	var err error

	// check rs.priv
	if rs.priv == nil {
		return nil, errors.New("rsaSigner must be provided a *rsa.PrivateKey")
	}

	// hash
	h := rs.hash.New()
	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}

	// sign
	sig, err := rs.method.Sign(rand.Reader, rs.priv, rs.hash, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	// encode
	enc := make([]byte, b64.EncodedLen(len(sig)))
	b64.Encode(enc, sig)

	return enc, nil
}

// Verify creates a signature for buf, comparing it against the URL-safe base64
// encoded sig. If the sig is invalid, then ErrInvalidSignature will be
// returned.
func (rs *rsaSigner) Verify(buf, sig []byte) ([]byte, error) {
	var err error

	// check rs.pub
	if rs.pub == nil {
		return nil, errors.New("rsaSigner must be provided a *rsa.PublicKey")
	}

	// hash
	h := rs.hash.New()
	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}

	// decode
	dec, err := b64.DecodeString(string(sig))
	if err != nil {
		return nil, err
	}

	// verify
	err = rs.method.Verify(rs.pub, rs.hash, h.Sum(nil), dec)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	return dec, nil
}

// Encode encodes obj as a token.
func (rs *rsaSigner) Encode(obj interface{}) ([]byte, error) {
	return rs.alg.Encode(rs, obj)
}

// Decode decodes a serialized token, verifying the signature, storing the
// decoded data from the token in obj.
func (rs *rsaSigner) Decode(buf []byte, obj interface{}) error {
	return rs.alg.Decode(rs, buf, obj)
}
