// Package url provides a quick API to sign Google Storage URLs using Google
// Service Account Credentials.
//
// For an example, please see cmd/gurl in this repository.
package gurl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kenshaw/jwt/gserviceaccount"
	"github.com/kenshaw/pemutil"
)

const (
	// DefaultBaseURL is the base Google Storage URL.
	DefaultBaseURL = "https://storage.googleapis.com"

	// DefaultExpiration is the default expiration for signed URLs.
	DefaultExpiration = 1 * time.Hour
)

// Params are the signing params for generating a signed URL.
type Params struct {
	// BaseURL is the URL to use for building the URL. If not supplied, then
	// DefaultBaseURL will be used instead.
	BaseURL string

	// Method is the HTTP method (GET, PUT, ...).
	Method string

	// Hash is the md5 hash of the file content for an upload.
	Hash string

	// ContentType is the content type of the uploaded file.
	ContentType string

	// Expiration is the expiration time of a generated signature.
	Expiration time.Time

	// Headers are the extra headers.
	Headers map[string]string

	// Bucket is the storage bucket.
	Bucket string

	// Object is the object path.
	Object string
}

// HeaderString sorts the headers in order, returning an ordered, usable string
// for use with signing.
func (p Params) HeaderString() string {
	h := make([]string, len(p.Headers))
	headers := make(map[string]string)
	var i int
	for k, v := range p.Headers {
		k = strings.TrimSpace(strings.ToLower(k))
		if k != "x-goog-encryption-key" && k != "x-goog-encryption-key-sha256" {
			headers[k], h[i] = v, k
		}
		i++
	}
	if len(h) != 0 {
		sort.Slice(h, func(i, j int) bool {
			return strings.Compare(h[i], h[j]) < 0
		})
		for i, k := range h {
			h[i] += ":" + strings.TrimSpace(headers[k])
		}
		return strings.Join(h, "\n") + "\n"
	}
	return ""
}

// ObjectPath returns the canonical path.
func (p Params) ObjectPath() string {
	return "/" + strings.Trim(p.Bucket, "/") + "/" + strings.TrimPrefix(p.Object, "/")
}

// String satisfies the fmt.Stringer interface.
//
// Returns the ordered and formatted string suitable needed by Signer.
func (p Params) String() string {
	return p.Method + "\n" +
		p.Hash + "\n" +
		p.ContentType + "\n" +
		strconv.FormatInt(p.Expiration.Unix(), 10) + "\n" +
		p.HeaderString() +
		p.ObjectPath()
}

// Signer is a url signer that generates signed URLs for use with Google Cloud
// Storage.
type Signer struct {
	PrivateKey  *rsa.PrivateKey
	ClientEmail string
}

// New creates a new url signer.
func New() (*Signer, error) {
	return &Signer{}, nil
}

// Params generates and signs the provided URL parameters.
//
// Note: Please see the Sign method.
func (u *Signer) Params(p *Params) (string, error) {
	// hash
	h := crypto.SHA256.New()
	if _, err := h.Write([]byte(p.String())); err != nil {
		return "", err
	}
	// sign
	sig, err := rsa.SignPKCS1v15(rand.Reader, u.PrivateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return "", err
	}
	// base64 encode
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Sign creates the signature for the provided method, hash, contentType,
// bucket, and path accordingly.
func (u *Signer) Sign(method, hash, contentType, bucket, path string, headers map[string]string) (string, error) {
	return u.Params(&Params{
		Method:      method,
		Hash:        hash,
		ContentType: contentType,
		Headers:     headers,
		Bucket:      bucket,
		Object:      path,
	})
}

// Make creates and signs a URL using the specified params and duration.
func (u *Signer) Make(p *Params, d time.Duration) (string, error) {
	// set default expiration if duration supplied
	if d != 0 {
		p.Expiration = time.Now().Add(d)
	}
	// create sig
	sig, err := u.Params(p)
	if err != nil {
		return "", err
	}
	// create query
	v := url.Values{}
	v.Set("GoogleAccessId", u.ClientEmail)
	v.Set("Expires", strconv.FormatInt(p.Expiration.Unix(), 10))
	v.Set("Signature", sig)
	// base
	baseURL := p.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return baseURL + p.ObjectPath() + "?" + v.Encode(), nil
}

// MakeParams creates and signs a URL for the specified method, bucket, path,
// duration, and any additional headers.
func (u *Signer) MakeParams(method, bucket, path string, d time.Duration, headers map[string]string) (string, error) {
	return u.Make(&Params{
		Method:  method,
		Headers: headers,
		Bucket:  bucket,
		Object:  path,
	}, d)
}

// DownloadPath generates a signed path for downloading an object.
func (u *Signer) DownloadPath(bucket, path string) (string, error) {
	return u.MakeParams("GET", bucket, path, DefaultExpiration, nil)
}

// UploadPath generates a signed path for uploading an object.
func (u *Signer) UploadPath(bucket, path string) (string, error) {
	return u.MakeParams("PUT", bucket, path, DefaultExpiration, nil)
}

// DeletePath generates a signed path for deleting an object.
func (u *Signer) DeletePath(bucket, path string) (string, error) {
	return u.MakeParams("DELETE", bucket, path, DefaultExpiration, nil)
}

// FromJSON is an option that loads Google Service Account credentials
// from a JSON encoded buf to create a url signer.
//
// Google Service Account credentials can be downloaded from the Google Cloud
// console: https://console.cloud.google.com/iam-admin/serviceaccounts/
func FromJSON(buf []byte) (*Signer, error) {
	// load service account credentials
	gsa, err := gserviceaccount.FromJSON(buf)
	if err != nil {
		return nil, err
	}
	// check client email and private key
	if gsa.ClientEmail == "" || gsa.PrivateKey == "" {
		return nil, errors.New("google service accoount credentials missing client_email or private_key")
	}
	// load key
	s := pemutil.Store{}
	if err = s.Decode([]byte(gsa.PrivateKey)); err != nil {
		return nil, err
	}
	// grab privKey
	privateKey, ok := s[pemutil.RSAPrivateKey].(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("google service account credentials has an invalid private_key")
	}
	return &Signer{
		PrivateKey:  privateKey,
		ClientEmail: gsa.ClientEmail,
	}, nil
}

// FromFile creates a new Google URL Signer from Google Service Account.
//
// Google Service Account credentials can be downloaded from the Google Cloud
// console: https://console.cloud.google.com/iam-admin/serviceaccounts/
func FromFile(path string) (*Signer, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read google service account credentials file: %v", err)
	}
	return FromJSON(buf)
}
