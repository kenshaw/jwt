// Package bearer provides a generic oauth2.TokenSource for JWT Bearer Grant
// Assertions.
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

// Bearer provides a JWT Bearer Grant oauth2.TokenSource that handles redeeming
// tokens using the JWT bearer grant assertion auth flow.
//
// This should be wrapped with a oauth2.ReusableTokenSource before using it
// with oauth2.Transport.
type Bearer struct {
	signer    jwt.Signer
	tokenURL  string
	context   context.Context
	transport http.RoundTripper

	addExpiration bool
	addIssuedAt   bool
	addNotBefore  bool

	expiresIn time.Duration

	claims map[string]interface{}
}

// NewTokenSource creates a oauth2.TokenSource that generates auth tokens
// redeemed using the JWT Bearer Grant assertion auth flow using the supplied
// jwt.Signer. A token redemption will be invoked at the tokenURL using the
// supplied context.
//
// Use the Claim option to pass additional claims to the token source.
func NewTokenSource(signer jwt.Signer, tokenURL string, ctxt context.Context, opts ...Option) (*Bearer, error) {
	var err error
	b := &Bearer{
		signer:   signer,
		tokenURL: tokenURL,
		context:  ctxt,
		claims:   make(map[string]interface{}),
	}
	// apply opts
	for _, o := range opts {
		if err = o(b); err != nil {
			return nil, fmt.Errorf("jwt/bearer: %v", err)
		}
	}
	return b, nil
}

// Token satisfies the oauth2.TokenSource interface.
func (b *Bearer) Token() (*oauth2.Token, error) {
	var err error
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
	err = json.Unmarshal(body, &tv)
	if err != nil {
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

// Client returns a HTTP client using the bearer token.
func (b *Bearer) Client() *http.Client {
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: b,
		},
	}
}

// Option represents a Bearer option.
type Option func(*Bearer) error

// WithExpiresIn is an option that will set the expiration duration generated
// for tokens to the specified duration.
func WithExpiresIn(d time.Duration) Option {
	return func(tok *Bearer) error {
		if d != 0 {
			tok.addExpiration = true
			tok.expiresIn = d
		} else {
			tok.addExpiration = false
			tok.expiresIn = 0
		}
		return nil
	}
}

// WithIssuedAt is an option that toggles whether or not the Issued At ("iat")
// field is generated for the token.
func WithIssuedAt(enable bool) Option {
	return func(tok *Bearer) error {
		tok.addIssuedAt = enable
		return nil
	}
}

// WithNotBefore is an option that toggles whether or not the Not Before
// ("nbf") field is generated for the token.
func WithNotBefore(enable bool) Option {
	return func(tok *Bearer) error {
		tok.addNotBefore = enable
		return nil
	}
}

// WithClaim is an option that adds an additional claim that is generated with
// the token.
func WithClaim(name string, v interface{}) Option {
	return func(tok *Bearer) error {
		if tok.claims == nil {
			return errors.New("attempting to add claim to improperly created token")
		}
		tok.claims[name] = v
		return nil
	}
}

// WithScope is an option that adds a Scope ("scope") field to generated
// tokens. Scopes are joined with a space (" ") separator.
func WithScope(scopes ...string) Option {
	return func(tok *Bearer) error {
		if len(scopes) > 0 {
			return WithClaim("scope", strings.Join(scopes, " "))(tok)
		}
		return nil
	}
}

// WithTransport is an option that sets an underlying client transport to the
// exchange process.
func WithTransport(transport http.RoundTripper) Option {
	return func(tok *Bearer) error {
		tok.transport = transport
		return nil
	}
}
