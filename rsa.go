package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"

	"github.com/knq/pemutil"
)

// rsaMethod provides a common wrapper for different rsa signing methods.
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

// rsaSigner provides a Signer for RSA.
type rsaSigner struct {
	method rsaMethod
	hash   crypto.Hash
	priv   *rsa.PrivateKey
	pub    *rsa.PublicKey
}

// NewRSASigner creates an RSA Signer for the specified RSA method.
func NewRSASigner(method rsaMethod) func(PEM, crypto.Hash) Signer {
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
			hash:   hash,
			method: method,
			priv:   priv,
			pub:    pub,
		}
	}
}

// Sign creates a signature for buf, storing it as a base64 safe string in dst.
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

// Verify creates a signature for buf, and compares it against the base64
// encoded sig, returning any errors or ErrInvalidSignature if they do not
// match.
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
