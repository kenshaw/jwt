package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"

	"github.com/knq/pemutil"
)

// hmacSigner provides a Signer implementation for HMAC.
type hmacSigner struct {
	hash crypto.Hash
	key  []byte
}

// NewHMACSigner constructs a HMAC Signer.
func NewHMACSigner(pem PEM, hash crypto.Hash) Signer {
	store := loadKeysFromPEM(pem)

	var ok bool
	var keyRaw interface{}
	var key []byte

	if keyRaw, ok = store[pemutil.PrivateKey]; !ok {
		panic("NewHMACSigner must be supplied a key a private key")
	}

	if key, ok = keyRaw.([]byte); !ok {
		panic("NewHMACSigner must be supplied a key of type []byte")
	}

	return &hmacSigner{
		hash: hash,
		key:  key,
	}
}

// Sign creates a signature for buf, storing it as a base64 safe string in dst.
func (hs *hmacSigner) Sign(buf []byte) ([]byte, error) {
	var err error

	// check hs.key
	if hs.key == nil {
		return nil, errors.New("hmacSigner must be provided a key of type []byte")
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

// Verify creates a signature for buf, and compares it against the base64
// encoded sig, returning any errors or ErrInvalidSignature if they do not
// match.
func (hs *hmacSigner) Verify(buf, sig []byte) ([]byte, error) {
	var err error

	// check hs.key
	if hs.key == nil {
		return nil, errors.New("hmacSigner must be provided a key of type []byte")
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
