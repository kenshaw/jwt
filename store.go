package jwt

import (
	"crypto"
	"sync"
)

// Store is the common interface for a keystore.
type Store interface {
	// PublicKey returns the public key for a store.
	PublicKey() (crypto.PublicKey, bool)

	// PrivateKey returns the private key for a store.
	PrivateKey() (crypto.PrivateKey, bool)
}

// Keystore is a simple type providing a Store implementation.
type Keystore struct {
	// Key is the private key.
	Key interface{}

	// PublicKey is the public key.
	PubKey interface{}

	rw sync.RWMutex
}

// PublicKey returns the stored public key for the keystore, alternately
// generating the public key from the private key if the public key was not
// supplied and the private key was.
func (s *Keystore) PublicKey() (crypto.PublicKey, bool) {
	s.rw.RLock()
	key, pub := s.Key, s.PubKey
	s.rw.RUnlock()
	if pub != nil {
		return pub, true
	}
	// generate the public key
	if key != nil {
		s.rw.Lock()
		defer s.rw.Unlock()
		if x, ok := key.(interface {
			Public() crypto.PublicKey
		}); ok {
			s.PubKey = x.Public()
		}
		return s.PubKey, s.PubKey != nil
	}
	return nil, false
}

// PrivateKey returns the stored private key for the keystore.
func (s *Keystore) PrivateKey() (crypto.PrivateKey, bool) {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.Key, s.Key != nil
}
