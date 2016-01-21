package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/knq/pemutil"
)

// eccSigner provides a Signer for Elliptic Curves.
type eccSigner struct {
	alg   Algorithm
	curve elliptic.Curve
	hash  crypto.Hash
	priv  *ecdsa.PrivateKey
	pub   *ecdsa.PublicKey

	keyLen int
}

// NewEllipticSigner creates an Elliptic Curve Signer for the specified curve.
func NewEllipticSigner(alg Algorithm, curve elliptic.Curve) func(PEM, crypto.Hash) Signer {
	curveBitSize := curve.Params().BitSize

	// calculate key len
	keyLen := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyLen++
	}

	return func(pem PEM, hash crypto.Hash) Signer {
		store := loadKeysFromPEM(pem)

		var ok bool
		var privRaw, pubRaw interface{}
		var priv *ecdsa.PrivateKey
		var pub *ecdsa.PublicKey

		if privRaw, ok = store[pemutil.ECPrivateKey]; ok {
			if priv, ok = privRaw.(*ecdsa.PrivateKey); !ok {
				panic("private key supplied to NewEllipticSigner must be *ecdsa.PrivateKey")
			}

			// check curve
			if curveBitSize != priv.Curve.Params().BitSize {
				panic(fmt.Sprintf("private key supplied to NewEllipticSigner must have matching bit size [expected %d, got: %d]", curve.Params().BitSize, priv.Curve.Params().BitSize))
			}
		}

		if pubRaw, ok = store[pemutil.PublicKey]; ok {
			if pub, ok = pubRaw.(*ecdsa.PublicKey); !ok {
				panic("public key supplied to NewEllipticSigner must be *ecdsa.PublicKey")
			}
		}

		return &eccSigner{
			alg:    alg,
			curve:  curve,
			hash:   hash,
			priv:   priv,
			pub:    pub,
			keyLen: keyLen,
		}
	}
}

// mksig creates a byte slice of r and s, left padding both r and s to keyLen.
func (es *eccSigner) mksig(r, s *big.Int) ([]byte, error) {
	var n int

	buf := make([]byte, 2*es.keyLen)

	// copy r into buf
	rb := r.Bytes()
	n = copy(buf[es.keyLen-len(rb):], rb)
	if n != len(rb) {
		return nil, fmt.Errorf("could not copy r into sig, copied: %d", n)
	}

	// copy s into buf
	sb := s.Bytes()
	n = copy(buf[es.keyLen+(es.keyLen-(len(sb))):], sb)
	if n != len(sb) {
		return nil, fmt.Errorf("could not copy s into sig, copied: %d", n)
	}

	return buf, nil
}

// Sign creates a signature for buf, storing it as a base64 safe string in dst.
func (es *eccSigner) Sign(buf []byte) ([]byte, error) {
	var err error

	// check es.priv
	if es.priv == nil {
		return nil, errors.New("eccSigner must be provided a *ecdsa.PrivateKey")
	}

	// hash
	h := es.hash.New()
	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}

	// sign
	r, s, err := ecdsa.Sign(rand.Reader, es.priv, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	// make sig
	sig, err := es.mksig(r, s)
	if err != nil {
		return nil, err
	}

	// encode
	enc := make([]byte, b64.EncodedLen(len(sig)))
	b64.Encode(enc, sig)

	return enc, nil
}

// Verify creates a signature for buf, and compares it against sig,
// returning ErrInvalidSignature if sig is not a valid signature.
func (es *eccSigner) Verify(buf, sig []byte) ([]byte, error) {
	var err error

	// check es.pub
	if es.pub == nil {
		return nil, errors.New("eccSigner must be provided a *ecdsa.PublicKey")
	}

	// hash
	h := es.hash.New()
	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}

	// decode
	dec, err := b64.DecodeString(string(sig))
	if err != nil {
		return nil, err
	}
	r := big.NewInt(0).SetBytes(dec[:es.keyLen])
	s := big.NewInt(0).SetBytes(dec[es.keyLen:])

	// verify
	if !ecdsa.Verify(es.pub, h.Sum(nil), r, s) {
		return nil, ErrInvalidSignature
	}

	return dec, nil
}

// Encode encodes a claim as a JSON token
func (es *eccSigner) Encode(obj interface{}) ([]byte, error) {
	return es.alg.Encode(es, obj)
}

// Decode decodes a serialized token, storing in obj and verifies the
// signature.
func (es *eccSigner) Decode(buf []byte, obj interface{}) error {
	return es.alg.Decode(es, buf, obj)
}
