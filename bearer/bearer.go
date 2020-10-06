// Package bearer provides a generic oauth2.TokenSource for JWT Bearer Grant
// Assertions.
//
// Please see the gserviceaccount package in this repository for an example of
// how to use the JWT bearer token source.
package bearer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenshaw/jwt"
	"golang.org/x/oauth2"
)

// GrantType is the JWT grant type assertion value.
const GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// Bearer provides a JWT based, oauth2 token source that generates tokens
// for redemption with the JWT bearer grant assertion auth flow.
//
// This token source can be used with an oauth2 transport to transparently
// authenticate a client's HTTP requests, and would typically be used with
// golang.org/x/oauth2.Transport and Go's standard http.Client.
//
// This bearer token source should be wrapped by a oauth2.ReusableTokenSource
// before using with oauth2.Transport.
type Bearer struct {
	signer        jwt.Signer
	tokenURL      string
	context       context.Context
	transport     http.RoundTripper
	addExpiration bool
	addIssuedAt   bool
	addNotBefore  bool
	expiresIn     time.Duration
	claims        map[string]interface{}
}

// NewTokenSource creates a oauth2.TokenSource that generates auth tokens
// redeemed using the JWT Bearer Grant assertion auth flow using the supplied
// jwt.Signer. A token redemption will be invoked at the tokenURL using the
// supplied context.
//
// Use WithClaim option to pass additional claims to the token source such as
// token subject or scope.
func NewTokenSource(signer jwt.Signer, tokenURL string, ctx context.Context, opts ...Option) (*Bearer, error) {
	b := &Bearer{
		signer:   signer,
		tokenURL: tokenURL,
		context:  ctx,
		claims:   make(map[string]interface{}),
	}
	// apply opts
	for _, o := range opts {
		if err := o(b); err != nil {
			return nil, fmt.Errorf("jwt/bearer: %v", err)
		}
	}
	return b, nil
}

// Token satisfies the oauth2.TokenSource interface.
func (b *Bearer) Token() (*oauth2.Token, error) {
	claims := make(map[string]interface{}, len(b.claims))
	for k, val := range b.claims {
		claims[k] = val
	}
	now := time.Now()
	n := json.Number(strconv.FormatInt(now.Unix(), 10))
	// add expiration
	if b.addExpiration {
		claims["exp"] = json.Number(strconv.FormatInt(now.Add(b.expiresIn).Unix(), 10))
	}
	// add issued at
	if b.addIssuedAt {
		claims["iat"] = n
	}
	// add not before
	if b.addNotBefore {
		claims["nbf"] = n
	}
	// encode token
	buf, err := b.signer.Encode(claims)
	if err != nil {
		return nil, fmt.Errorf("jwt/bearer: could not encode claims: %v", err)
	}
	// build client
	client := oauth2.NewClient(b.context, nil)
	client.Transport = b.transport
	// create values
	v := url.Values{}
	v.Set("grant_type", GrantType)
	v.Set("assertion", string(buf))
	// do assertion
	res, err := client.PostForm(b.tokenURL, v)
	if err != nil {
		return nil, fmt.Errorf("jwt/bearer: cannot do token assertion: %v", err)
	}
	defer res.Body.Close()
	// read response
	body, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("jwt/bearer: cannot fetch token: %v", err)
	}
	// check status code
	if c := res.StatusCode; c < 200 || c > 299 {
		return nil, fmt.Errorf("jwt/bearer: cannot fetch token: %s (%d): %s", res.Status, res.StatusCode, string(body))
	}
	// decode body
	var tv struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	// unmarhsal returned token
	if err = json.Unmarshal(body, &tv); err != nil {
		return nil, fmt.Errorf("jwt/bearer: cannot fetch token: %v", err)
	}
	ret := &oauth2.Token{
		AccessToken: tv.AccessToken,
		TokenType:   tv.TokenType,
	}
	// check passed expiration time
	if secs := tv.ExpiresIn; secs > 0 {
		ret.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	if tv.IDToken != "" {
		var e struct {
			Expiration int64 `json:"exp"`
		}
		// decode returned id_token to get expiration
		err = b.signer.Decode([]byte(tv.IDToken), &e)
		if err != nil {
			return nil, fmt.Errorf("jwt/bearer: could not decode id_token: %v", err)
		}
		ret.Expiry = time.Unix(e.Expiration, 0)
	}
	return ret, nil
}

// Client returns a HTTP client with an oauth2 transport using the bearer token
// source.
func (b *Bearer) Client() *http.Client {
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: b,
			Base:   b.transport,
		},
	}
}

// Option is a bearer token source option.
type Option func(*Bearer) error

// WithExpiresIn is a bearer token source option that sets the expiration
// duration for generated tokens.
func WithExpiresIn(d time.Duration) Option {
	return func(b *Bearer) error {
		if d != 0 {
			b.addExpiration = true
			b.expiresIn = d
		} else {
			b.addExpiration = false
			b.expiresIn = 0
		}
		return nil
	}
}

// WithIssuedAt is a bearer token source option that adds the Issued At ("iat")
// field to generated tokens.
func WithIssuedAt(enable bool) Option {
	return func(b *Bearer) error {
		b.addIssuedAt = enable
		return nil
	}
}

// WithNotBefore is a bearer token source option that adds the Not Before
// ("nbf") field to generated tokens.
func WithNotBefore(enable bool) Option {
	return func(b *Bearer) error {
		b.addNotBefore = enable
		return nil
	}
}

// WithClaim is a bearer token source option that adds additional claims to
// generated tokens.
func WithClaim(name string, v interface{}) Option {
	return func(b *Bearer) error {
		if b.claims == nil {
			return errors.New("attempting to add claim to improperly created token")
		}
		b.claims[name] = v
		return nil
	}
}

// WithSubject is a bearer token source option that adds the Subject ("sub")
// claim to generated tokens.
func WithSubject(subject string) Option {
	return func(b *Bearer) error {
		return WithClaim("sub", subject)(b)
	}
}

// WithScope is a bearer token source option that adds a Scope ("scope") claim
// to generated tokens.
//
// Note: Scopes are joined with a space (" "). Use WithClaim option if a
// different separator is required.
func WithScope(scopes ...string) Option {
	return func(b *Bearer) error {
		if len(scopes) > 0 {
			return WithClaim("scope", strings.Join(scopes, " "))(b)
		}
		return nil
	}
}

// WithTransport is a bearer token source option that sets the HTTP client
// transport to use during token exchange.
func WithTransport(transport http.RoundTripper) Option {
	return func(b *Bearer) error {
		b.transport = transport
		return nil
	}
}
