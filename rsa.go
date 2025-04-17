package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
)

// RSAMinimumBitLen is the minimum accepted RSA key length.
const RSAMinimumBitLen = 2048

// RSASignerVerifier provides a standardized interface to low level RSA signing
// implementation.
//
// This is used internally to provide a common interface to the RSA Sign/Verify
// implementations for PKCS1v15 and PSS.
type RSASignerVerifier interface {
	// Sign signs data in buf using rand, priv and hash.
	Sign(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, buf []byte) ([]byte, error)

	// Verify verifies the signature sig against using pub, hash, and the
	// hashed data.
	Verify(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error
}

// RSAMethod provides a wrapper for rsa signing methods.
type RSAMethod struct {
	SignFunc   func(io.Reader, *rsa.PrivateKey, crypto.Hash, []byte) ([]byte, error)
	VerifyFunc func(*rsa.PublicKey, crypto.Hash, []byte, []byte) error
}

// Sign signs the data in buf using rand, priv and hash.
func (m RSAMethod) Sign(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, buf []byte) ([]byte, error) {
	return m.SignFunc(rand, priv, hash, buf)
}

// Verify verifies the signature sig against using pub, hash, and the hashed
// data.
func (m RSAMethod) Verify(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
	return m.VerifyFunc(pub, hash, hashed, sig)
}

// RSAMethodPKCS1v15 provides a RSA method that signs and verifies with
// PKCS1v15.
var RSAMethodPKCS1v15 = RSAMethod{
	SignFunc:   rsa.SignPKCS1v15,
	VerifyFunc: rsa.VerifyPKCS1v15,
}

// RSAMethodPSS provides a RSA method that signs and verifies with PSS.
var RSAMethodPSS = RSAMethod{
	SignFunc: func(rand io.Reader, priv *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
		return rsa.SignPSS(rand, priv, hash, hashed, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		})
	},
	VerifyFunc: func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
		return rsa.VerifyPSS(pub, hash, hashed, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		})
	},
}

// RSASigner provides a RSA Signer.
type RSASigner struct {
	alg    Algorithm
	method RSASignerVerifier
	hash   crypto.Hash
	priv   *rsa.PrivateKey
	pub    *rsa.PublicKey
}

// NewRSASigner creates an RSA Signer for the specified Algorithm and provided
// low level RSA implementation.
func NewRSASigner(alg Algorithm, method RSASignerVerifier) func(Store, crypto.Hash) (Signer, error) {
	return func(store Store, hash crypto.Hash) (Signer, error) {
		var ok bool
		var privRaw, pubRaw any
		var priv *rsa.PrivateKey
		var pub *rsa.PublicKey
		// check private key
		if privRaw, ok = store.PrivateKey(); ok {
			if priv, ok = privRaw.(*rsa.PrivateKey); !ok {
				return nil, ErrInvalidPrivateKey
			}
			// check private key length
			if priv.N.BitLen() < RSAMinimumBitLen {
				return nil, ErrInvalidPrivateKeySize
			}
		}
		// check public key
		if pubRaw, ok = store.PublicKey(); ok {
			if pub, ok = pubRaw.(*rsa.PublicKey); !ok {
				return nil, ErrInvalidPublicKey
			}
			// check public key length
			if pub.N.BitLen() < RSAMinimumBitLen {
				return nil, ErrInvalidPublicKeySize
			}
		}
		// check that either a private or public key has been provided
		if priv == nil && pub == nil {
			return nil, ErrMissingPrivateOrPublicKey
		}
		return &RSASigner{
			alg:    alg,
			method: method,
			hash:   hash,
			priv:   priv,
			pub:    pub,
		}, nil
	}
}

// SignBytes creates a signature for buf.
func (s *RSASigner) SignBytes(buf []byte) ([]byte, error) {
	// check rs.priv
	if s.priv == nil {
		return nil, ErrMissingPrivateKey
	}
	// hash
	h := s.hash.New()
	if _, err := h.Write(buf); err != nil {
		return nil, err
	}
	// sign
	return s.method.Sign(rand.Reader, s.priv, s.hash, h.Sum(nil))
}

// Sign creates a signature for buf, returning it as a URL-safe base64 encoded
// byte slice.
func (s *RSASigner) Sign(buf []byte) ([]byte, error) {
	sig, err := s.SignBytes(buf)
	if err != nil {
		return nil, err
	}
	// encode
	enc := make([]byte, b64.EncodedLen(len(sig)))
	b64.Encode(enc, sig)
	return enc, nil
}

// VerifyBytes creates a signature for buf, comparing it against the raw sig.
// If the sig is invalid, then ErrInvalidSignature is returned.
func (s *RSASigner) VerifyBytes(buf, sig []byte) error {
	// check rs.pub
	if s.pub == nil {
		return ErrMissingPublicKey
	}
	// hash
	h := s.hash.New()
	if _, err := h.Write(buf); err != nil {
		return err
	}
	// verify
	if err := s.method.Verify(s.pub, s.hash, h.Sum(nil), sig); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// Verify creates a signature for buf, comparing it against the URL-safe base64
// encoded sig and returning the decoded signature. If the sig is invalid, then
// ErrInvalidSignature will be returned.
func (s *RSASigner) Verify(buf, sig []byte) ([]byte, error) {
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
func (s *RSASigner) Encode(obj any) ([]byte, error) {
	return s.alg.Encode(s, obj)
}

// Decode decodes a serialized token, verifying the signature, storing the
// decoded data from the token in obj.
func (s *RSASigner) Decode(buf []byte, obj any) error {
	return s.alg.Decode(s, buf, obj)
}
