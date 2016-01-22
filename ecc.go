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

// eccSigner provides an Elliptic Curve Signer.
type eccSigner struct {
	alg   Algorithm
	curve elliptic.Curve
	hash  crypto.Hash
	priv  *ecdsa.PrivateKey
	pub   *ecdsa.PublicKey

	keyLen int
}

// NewEllipticSigner creates an Elliptic Curve Signer for the specified curve.
func NewEllipticSigner(alg Algorithm, curve elliptic.Curve) func(pemutil.Store, crypto.Hash) Signer {
	curveBitSize := curve.Params().BitSize

	// calculate key len
	keyLen := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyLen++
	}

	return func(store pemutil.Store, hash crypto.Hash) Signer {
		var ok bool
		var privRaw, pubRaw interface{}
		var priv *ecdsa.PrivateKey
		var pub *ecdsa.PublicKey

		if privRaw, ok = store[pemutil.ECPrivateKey]; ok {
			if priv, ok = privRaw.(*ecdsa.PrivateKey); !ok {
				panic("NewEllipticSigner: private key must be a *ecdsa.PrivateKey")
			}

			// check curve
			if curveBitSize != priv.Curve.Params().BitSize {
				panic(fmt.Sprintf("NewEllipticSigner: private key have bit size %d", curve.Params().BitSize))
			}
		}

		if pubRaw, ok = store[pemutil.PublicKey]; ok {
			if pub, ok = pubRaw.(*ecdsa.PublicKey); !ok {
				panic("NewEllipticSigner: public key must be a *ecdsa.PublicKey")
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

// mksig creates a byte slice of length 2*keyLen, copying the bytes from r and
// s into it, and left padding the bytes of r and s as needed.
func (es *eccSigner) mksig(r, s *big.Int) ([]byte, error) {
	var n int

	buf := make([]byte, 2*es.keyLen)

	// copy r into buf
	rb := r.Bytes()
	n = copy(buf[es.keyLen-len(rb):], rb)
	if n != len(rb) {
		return nil, fmt.Errorf("eccSigner.mksig: could not copy r into sig, copied: %d", n)
	}

	// copy s into buf
	sb := s.Bytes()
	n = copy(buf[es.keyLen+(es.keyLen-(len(sb))):], sb)
	if n != len(sb) {
		return nil, fmt.Errorf("eccSigner.mksig: could not copy s into sig, copied: %d", n)
	}

	return buf, nil
}

// Sign creates a signature for buf, returning it as a URL-safe base64 encoded
// byte slice.
func (es *eccSigner) Sign(buf []byte) ([]byte, error) {
	var err error

	// check es.priv
	if es.priv == nil {
		return nil, errors.New("eccSigner.Sign: priv cannot be nil")
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

// Verify creates a signature for buf, comparing it against the URL-safe base64
// encoded sig. If the sig is invalid, then ErrInvalidSignature will be
// returned.
func (es *eccSigner) Verify(buf, sig []byte) ([]byte, error) {
	var err error

	// check es.pub
	if es.pub == nil {
		return nil, errors.New("eccSigner.Verify: pub cannot be nil")
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

// Encode encodes obj as a JSON token.
func (es *eccSigner) Encode(obj interface{}) ([]byte, error) {
	return es.alg.Encode(es, obj)
}

// Decode decodes a serialized token, verifying the signature, storing the
// decoded data from the token in obj.
func (es *eccSigner) Decode(buf []byte, obj interface{}) error {
	return es.alg.Decode(es, buf, obj)
}
