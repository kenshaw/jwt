package jwt

import (
	"crypto"
	"crypto/hmac"
)

// HmacSigner provides a HMAC Signer.
type HmacSigner struct {
	alg  Algorithm
	hash crypto.Hash
	key  []byte
}

// NewHMACSigner creates a HMAC Signer for the specified Algorithm.
func NewHMACSigner(alg Algorithm) func(Store, crypto.Hash) (Signer, error) {
	return func(store Store, hash crypto.Hash) (Signer, error) {
		var ok bool
		var keyRaw interface{}
		var key []byte
		// check private key
		if keyRaw, ok = store.PrivateKey(); !ok {
			return nil, ErrMissingPrivateKey
		}
		// check key type
		if key, ok = keyRaw.([]byte); !ok {
			return nil, ErrInvalidPrivateKey
		}
		return &HmacSigner{
			alg:  alg,
			hash: hash,
			key:  key,
		}, nil
	}
}

// SignBytes creates a signature for buf.
func (s *HmacSigner) SignBytes(buf []byte) ([]byte, error) {
	// check hs.key
	if s.key == nil {
		return nil, ErrMissingPrivateKey
	}
	// hash
	h := hmac.New(s.hash.New, s.key)
	if _, err := h.Write(buf); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Sign creates a signature for buf, returning it as a URL-safe base64 encoded
// byte slice.
func (s *HmacSigner) Sign(buf []byte) ([]byte, error) {
	sig, err := s.SignBytes(buf)
	if err != nil {
		return nil, err
	}
	enc := make([]byte, b64.EncodedLen(len(sig)))
	b64.Encode(enc, sig)
	return enc, nil
}

// VerifyBytes creates a signature for buf, comparing it against the raw sig.
// If the sig is invalid, then ErrInvalidSignature is returned.
func (s *HmacSigner) VerifyBytes(buf, sig []byte) error {
	// check hs.key
	if s.key == nil {
		return ErrMissingPrivateKey
	}
	// hash
	h := hmac.New(s.hash.New, s.key)
	if _, err := h.Write(buf); err != nil {
		return err
	}
	// verify
	if !hmac.Equal(h.Sum(nil), sig) {
		return ErrInvalidSignature
	}
	return nil
}

// Verify creates a signature for buf, comparing it against the URL-safe base64
// encoded sig and returning the decoded signature. If the sig is invalid, then
// ErrInvalidSignature will be returned.
func (s *HmacSigner) Verify(buf, sig []byte) ([]byte, error) {
	// decode
	dec, err := b64.DecodeString(string(sig))
	if err != nil {
		return nil, err
	}
	// verify
	if err = s.VerifyBytes(buf, dec); err != nil {
		return nil, err
	}
	return dec, nil
}

// Encode serializes the JSON marshalable obj data as a JWT.
func (s *HmacSigner) Encode(obj interface{}) ([]byte, error) {
	return s.alg.Encode(s, obj)
}

// Decode decodes a serialized token, verifying the signature, storing the
// decoded data from the token in obj.
func (s *HmacSigner) Decode(buf []byte, obj interface{}) error {
	return s.alg.Decode(s, buf, obj)
}
