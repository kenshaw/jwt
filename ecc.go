package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// EccSigner provides an Elliptic Curve Signer.
type EccSigner struct {
	alg    Algorithm
	curve  elliptic.Curve
	hash   crypto.Hash
	priv   *ecdsa.PrivateKey
	pub    *ecdsa.PublicKey
	keyLen int
}

// NewEllipticSigner creates an Elliptic Curve Signer for the specified curve.
func NewEllipticSigner(alg Algorithm, curve elliptic.Curve) func(Store, crypto.Hash) (Signer, error) {
	// precompute curve key len
	curveBitSize := curve.Params().BitSize
	keyLen := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyLen++
	}
	return func(store Store, hash crypto.Hash) (Signer, error) {
		var ok bool
		var privRaw, pubRaw interface{}
		var priv *ecdsa.PrivateKey
		var pub *ecdsa.PublicKey
		// check private key
		if privRaw, ok = store.PrivateKey(); ok {
			if priv, ok = privRaw.(*ecdsa.PrivateKey); !ok {
				return nil, ErrInvalidPrivateKey
			}
			// check curve type matches private key curve type
			if curveBitSize != priv.Curve.Params().BitSize {
				return nil, ErrInvalidPrivateKeySize
			}
		}
		// check public key
		if pubRaw, ok = store.PublicKey(); ok {
			if pub, ok = pubRaw.(*ecdsa.PublicKey); !ok {
				return nil, ErrInvalidPublicKey
			}
		}
		// check that either a private or public key has been provided
		if priv == nil && pub == nil {
			return nil, ErrMissingPrivateOrPublicKey
		}
		return &EccSigner{
			alg:    alg,
			curve:  curve,
			hash:   hash,
			priv:   priv,
			pub:    pub,
			keyLen: keyLen,
		}, nil
	}
}

// Mksig creates a byte slice of length 2*keyLen, copying the bytes from r and
// s into the slice, left padding r and i to keyLen.
func (s *EccSigner) Mksig(r, i *big.Int) ([]byte, error) {
	buf := make([]byte, 2*s.keyLen)
	// copy r into buf
	rb := r.Bytes()
	if n := copy(buf[s.keyLen-len(rb):], rb); n != len(rb) {
		return nil, ErrMismatchedBytesCopied
	}
	// copy s into buf
	sb := i.Bytes()
	if n := copy(buf[s.keyLen+(s.keyLen-(len(sb))):], sb); n != len(sb) {
		return nil, ErrMismatchedBytesCopied
	}
	return buf, nil
}

// SignBytes creates a signature for buf.
func (s *EccSigner) SignBytes(buf []byte) ([]byte, error) {
	// check es.priv
	if s.priv == nil {
		return nil, ErrInvalidPrivateKey
	}
	// hash
	h := s.hash.New()
	if _, err := h.Write(buf); err != nil {
		return nil, err
	}
	// sign
	r, i, err := ecdsa.Sign(rand.Reader, s.priv, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	// make sig
	return s.Mksig(r, i)
}

// Sign creates a signature for buf, returning it as a URL-safe base64 encoded
// byte slice.
func (s *EccSigner) Sign(buf []byte) ([]byte, error) {
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
func (s *EccSigner) VerifyBytes(buf, sig []byte) error {
	// check es.pub
	if s.pub == nil {
		return ErrInvalidPublicKey
	}
	// hash
	h := s.hash.New()
	if _, err := h.Write(buf); err != nil {
		return err
	}
	// check decoded length
	if len(sig) != 2*s.keyLen {
		return ErrInvalidSignature
	}
	r := big.NewInt(0).SetBytes(sig[:s.keyLen])
	i := big.NewInt(0).SetBytes(sig[s.keyLen:])
	// verify
	if !ecdsa.Verify(s.pub, h.Sum(nil), r, i) {
		return ErrInvalidSignature
	}
	return nil
}

// Verify creates a signature for buf, comparing it against the URL-safe base64
// encoded sig and returning the decoded signature. If the sig is invalid, then
// ErrInvalidSignature will be returned.
func (s *EccSigner) Verify(buf, sig []byte) ([]byte, error) {
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
func (s *EccSigner) Encode(obj interface{}) ([]byte, error) {
	return s.alg.Encode(s, obj)
}

// Decode decodes a serialized token, verifying the signature, storing the
// decoded data from the token in obj.
func (s *EccSigner) Decode(buf []byte, obj interface{}) error {
	return s.alg.Decode(s, buf, obj)
}
