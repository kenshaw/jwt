// Package gserviceaccount provides a simple way to load Google service account
// credentials and create a corresponding oauth2.TokenSource from it.
package gserviceaccount

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"time"

	"golang.org/x/net/context"

	"github.com/knq/jwt"
	"github.com/knq/jwt/bearer"
)

const (
	// DefaultAlgorithm is the default jwt.Algothrithm to use with service
	// account tokens.
	DefaultAlgorithm = jwt.RS256

	// DefaultExpiration is the default token expiration duration to use with
	// service account tokens.
	DefaultExpiration = 1 * time.Hour
)

// GServiceAccount is the data contained within a JSON-encoded Google service
// account file.
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
}

// FromJSON loads service account credentials from the JSON encoded buf.
func FromJSON(buf []byte) (*GServiceAccount, error) {
	var gsa GServiceAccount

	// unmarshal
	err := json.Unmarshal(buf, &gsa)
	if err != nil {
		return nil, err
	}

	return &gsa, nil
}

// FromReader loads Google service account credentials from a reader.
func FromReader(r io.Reader) (*GServiceAccount, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return FromJSON(buf)
}

// FromFile loads Google service account credentials from a reader.
func FromFile(path string) (*GServiceAccount, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return FromJSON(buf)
}

// Signer returns a suitable jwt.Signer for use with the service account.
func (gsa *GServiceAccount) Signer() (jwt.Signer, error) {
	return DefaultAlgorithm.New(jwt.PEM{[]byte(gsa.PrivateKey)})
}

// TokenSource returns a reusable token source for the Google service account
// using the provided context and scopes.
//
// If context is empty, then then context.Background() will be used instead.
//
// If additional claims need to be added to the TokenSource (ie, subject or the
// "sub" field), use jwt/bearer.Claim to add them prior to wrapping the
// TokenSource with oauth2.ReusableTokenSource.
func (gsa *GServiceAccount) TokenSource(ctxt context.Context, scopes ...string) (*bearer.Bearer, error) {
	var err error

	// simple check that required fields are present
	if gsa.ClientEmail == "" || gsa.TokenURI == "" {
		return nil, errors.New("jwt/gserviceaccount: ClientEmail and TokenURI cannot be empty")
	}

	// set up subject and context
	if ctxt == nil {
		ctxt = context.Background()
	}

	// get signer
	signer, err := gsa.Signer()
	if err != nil {
		return nil, err
	}

	// bearer grant options
	opts := []bearer.Option{
		bearer.ExpiresIn(DefaultExpiration),
		bearer.IssuedAt(true),
		bearer.Claim("iss", gsa.ClientEmail),
		bearer.Claim("aud", gsa.TokenURI),
		bearer.Scope(scopes...),
	}

	// create token source
	b, err := bearer.NewTokenSource(
		signer,
		gsa.TokenURI,
		ctxt,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return b, nil
}
