// Package gserviceaccount provides a simple way to load Google service account
// credentials and create a corresponding oauth2.TokenSource from it.
package gserviceaccount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/kenshaw/jwt"
	"github.com/kenshaw/jwt/bearer"
	"github.com/kenshaw/pemutil"
)

const (
	// DefaultAlgorithm is the default jwt.Algothrithm to use with service
	// account tokens.
	DefaultAlgorithm = jwt.RS256

	// DefaultExpiration is the default token expiration duration to use with
	// service account tokens.
	DefaultExpiration = 1 * time.Hour
)

// GServiceAccount wraps Google Service Account parameters, and are the same
// values found in a standard JSON-encoded credentials file provided by Google.
type GServiceAccount struct {
	Type                    string `json:"type,omitempty"`
	ProjectID               string `json:"project_id,omitempty"`
	PrivateKeyID            string `json:"private_key_id,omitempty"`
	PrivateKey              string `json:"private_key,omitempty"`
	ClientEmail             string `json:"client_email,omitempty"`
	ClientID                string `json:"client_id,omitempty"`
	AuthURI                 string `json:"auth_uri,omitempty"`
	TokenURI                string `json:"token_uri,omitempty"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url,omitempty"`
	ClientX509CertURL       string `json:"client_x509_cert_url,omitempty"`

	expiration time.Duration          `json:"-"`
	signer     jwt.Signer             `json:"-"`
	transport  http.RoundTripper      `json:"-"`
	claims     map[string]interface{} `json:"-"`
	mu         sync.Mutex             `json:"-"`
}

// FromJSON loads service account credentials from the JSON encoded buf.
func FromJSON(buf []byte, opts ...Option) (*GServiceAccount, error) {
	var err error
	// unmarshal
	gsa := &GServiceAccount{
		claims: make(map[string]interface{}),
	}
	if err = json.Unmarshal(buf, gsa); err != nil {
		return nil, err
	}
	// apply opts
	for _, o := range opts {
		if err = o(gsa); err != nil {
			return nil, err
		}
	}
	return gsa, nil
}

// FromReader loads Google service account credentials from a reader.
func FromReader(r io.Reader, opts ...Option) (*GServiceAccount, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return FromJSON(buf, opts...)
}

// FromFile loads Google service account credentials from a reader.
func FromFile(path string, opts ...Option) (*GServiceAccount, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromJSON(buf, opts...)
}

// Signer returns a jwt.Signer for use when signing tokens.
func (gsa *GServiceAccount) Signer() (jwt.Signer, error) {
	gsa.mu.Lock()
	defer gsa.mu.Unlock()
	if gsa.signer == nil {
		keyset, err := pemutil.DecodeBytes([]byte(gsa.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("jwt/gserviceaccount: could not decode private key: %v", err)
		}
		keyset.AddPublicKeys()
		s, err := DefaultAlgorithm.New(keyset)
		if err != nil {
			return nil, err
		}
		gsa.signer = s
	}
	return gsa.signer, nil
}

// TokenSource returns a oauth2.TokenSource for the Google Service Account
// using the provided context and scopes. The resulting token source should be
// wrapped with oauth2.ReusableTokenSource prior to being used elsewhere.
//
// If additional claims need to be added to the TokenSource (ie, subject or the
// "sub" field), use WithClaim option to add claims before wrapping the
// TokenSource with oauth2.ReusableTokenSource.
func (gsa *GServiceAccount) TokenSource(ctx context.Context, scopes ...string) (*bearer.Bearer, error) {
	switch {
	case gsa.Type != "service_account":
		return nil, errors.New("jwt/gserviceaccount: type is not service_account")
	case gsa.ClientEmail == "":
		return nil, errors.New("jwt/gserviceaccount: missing client_email")
	case gsa.TokenURI == "":
		return nil, errors.New("jwt/gserviceaccount: missing token_uri")
	}
	// get signer
	signer, err := gsa.Signer()
	if err != nil {
		return nil, err
	}
	// determine expiration
	expiration := gsa.expiration
	if expiration == 0 {
		expiration = DefaultExpiration
	}
	// bearer grant options
	opts := []bearer.Option{
		bearer.WithExpiresIn(expiration),
		bearer.WithIssuedAt(true),
		bearer.WithClaim("iss", gsa.ClientEmail),
		bearer.WithClaim("aud", gsa.TokenURI),
		bearer.WithScope(scopes...),
	}
	for k, v := range gsa.claims {
		opts = append(opts, bearer.WithClaim(k, v))
	}
	// add transport
	if gsa.transport != nil {
		opts = append(opts, bearer.WithTransport(gsa.transport))
	}
	// create token source
	b, err := bearer.NewTokenSource(
		signer,
		gsa.TokenURI,
		ctx,
		opts...,
	)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Client returns a HTTP client using the provided context and scopes for the
// service account as the underlying transport.
//
// When called with the appropriate scopes, the created client can be used to
// create any Google API Service:
//
// 		import (
// 			dns "google.golang.org/api/dns/v2beta1"
//      )
//      cl, err := gsa.Client(ctx, dns.CloudPlatformScope, dns.NdevClouddnsReadwriteScope)
// 		if err != nil { /* ... */ }
//      dnsService, err := dns.New(cl)
// 		if err != nil { /* ... */ }
//
// Note: this is a convenience func only.
func (gsa *GServiceAccount) Client(ctx context.Context, scopes ...string) (*http.Client, error) {
	b, err := gsa.TokenSource(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	return b.Client(), nil
}

// Option is a GServiceAccount option.
type Option func(*GServiceAccount) error

// WithTransport is a GServiceAccount option to set the client transport used
// by the token source.
func WithTransport(transport http.RoundTripper) Option {
	return func(gsa *GServiceAccount) error {
		gsa.transport = transport
		return nil
	}
}

// WithProxy is a GServiceAccount option to set a HTTP proxy used for by the
// token source.
func WithProxy(proxy string) Option {
	return func(gsa *GServiceAccount) error {
		u, err := url.Parse(proxy)
		if err != nil {
			return err
		}
		return WithTransport(&http.Transport{
			Proxy: http.ProxyURL(u),
		})(gsa)
	}
}

// WithExpiration is a GServiceAccount option to set a expiration limit for
// tokens generated from the token source.
func WithExpiration(expiration time.Duration) Option {
	return func(gsa *GServiceAccount) error {
		gsa.expiration = expiration
		return nil
	}
}

// WithClaim is a GServiceAccount option to set additional claims for tokens
// generated from the token source.
func WithClaim(name string, v interface{}) Option {
	return func(gsa *GServiceAccount) error {
		gsa.claims[name] = v
		return nil
	}
}

// WithSubject is a GServiceAccount option to set a subject ("sub") claim for
// tokens generated from the token source.
//
// This is useful when using domain-wide delegation to impersonate a user.
//
// Example:
//
// 	import (
// 		"github.com/kenshaw/jwt/gserviceaccount"
// 		admin "google.golang.org/api/admin/directory/v1"
// 	)
// 	func main() {
// 		gsa, err := gserviceaccount.FromFile("/path/to/gsa.json", gserviceaccount.WithSubject("user@example.com"))
// 		if err != nil { /* ... */ }
// 		cl, err := gsa.Client()
// 		if err != nil { /* ... */ }
// 		adminService, err := admin.New(cl)
// 		if err != nil { /* ... */ }
// 		users, err := adminService.Users.Domain("example.com").List()
// 		if err != nil { /* ... */ }
// 		for _, u := range users.Users { /* ... */ }
// 	}
func WithSubject(sub string) Option {
	return func(gsa *GServiceAccount) error {
		return WithClaim("sub", sub)(gsa)
	}
}
