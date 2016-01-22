package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"

	"github.com/knq/pemutil"
)

// hmacSigner provides a HMAC Signer.
type hmacSigner struct {
	alg  Algorithm
	hash crypto.Hash
	key  []byte
}

// NewHMACSigner creates a HMAC Signer for the specified Algorithm.
func NewHMACSigner(alg Algorithm) func(pemutil.Store, crypto.Hash) Signer {
	return func(store pemutil.Store, hash crypto.Hash) Signer {
		var ok bool
		var keyRaw interface{}
		var key []byte

		// check private key
		if keyRaw, ok = store[pemutil.PrivateKey]; !ok {
			panic("NewHMACSigner: private key must be provided")
		}

		// check key type
		if key, ok = keyRaw.([]byte); !ok {
			panic("NewHMACSigner: private key must be type []byte")
		}

		return &hmacSigner{
			alg:  alg,
			hash: hash,
			key:  key,
		}
	}
}

// Sign creates a signature for buf, returning it as a URL-safe base64 encoded
// byte slice.
func (hs *hmacSigner) Sign(buf []byte) ([]byte, error) {
	var err error

	// check hs.key
	if hs.key == nil {
		return nil, errors.New("hmacSigner.Sign: key cannot be nil")
	}

	// hash
	h := hmac.New(hs.hash.New, hs.key)
	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}
	sig := h.Sum(nil)

	// encode
	enc := make([]byte, b64.EncodedLen(len(sig)))
	b64.Encode(enc, sig)

	return enc, nil
}

// Verify creates a signature for buf, comparing it against the URL-safe base64
// encoded sig. If the sig is invalid, then ErrInvalidSignature will be
// returned.
func (hs *hmacSigner) Verify(buf, sig []byte) ([]byte, error) {
	var err error

	// check hs.key
	if hs.key == nil {
		return nil, errors.New("hmacSigner.Verify: key cannot be nil")
	}

	// hash
	h := hmac.New(hs.hash.New, hs.key)
	_, err = h.Write(buf)
	if err != nil {
		return nil, err
	}
	calcSig := h.Sum(nil)

	// decode
	dec, err := b64.DecodeString(string(sig))
	if err != nil {
		return nil, err
	}

	// verify
	if !hmac.Equal(calcSig, dec) {
		return nil, ErrInvalidSignature
	}

	return dec, nil
}

// Encode encodes obj as a JSON token.
func (hs *hmacSigner) Encode(obj interface{}) ([]byte, error) {
	return hs.alg.Encode(hs, obj)
}

// Decode decodes a serialized token, verifying the signature, storing the
// decoded data from the token in obj.
func (hs *hmacSigner) Decode(buf []byte, obj interface{}) error {
	return hs.alg.Decode(hs, buf, obj)
}
