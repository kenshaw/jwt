package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/knq/pemutil"
)

var (
	// b64 is the base64 config used for encoding/decoding the jwt parts.
	b64 = base64.URLEncoding.WithPadding(base64.NoPadding)

	// ErrInvalidSignature is the error when a signature is invalid.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidAlgorithm is the error when the algorithm used in the header
	// doesn't match with the Signer's.
	ErrInvalidAlgorithm = errors.New("invalid algorithm")

	// ErrInvalidToken is the error when the JWT is improperly formatted.
	ErrInvalidToken = errors.New("invalid token")
)

// loadKeysFromPEM loads keys in the PEM, returning a pemutil.Store containing
// the loaded crypto primitives (ie, rsa.PrivateKey, ecdsa.PrivateKey, etc).
func loadKeysFromPEM(pem pemutil.PEM) (pemutil.Store, error) {
	// attempt to load crypto primitives
	store := pemutil.Store{}
	err := pem.Load(store)
	if err != nil {
		return nil, err
	}

	return store, nil
}

// getFieldWithTag lookups jwt tag, with specified tagName on obj, returning
// its reflected value.
func getFieldWithTag(obj interface{}, tagName string) *reflect.Value {
	objValElem := reflect.ValueOf(obj).Elem()

	for i := 0; i < objValElem.NumField(); i++ {
		fieldType := objValElem.Type().Field(i)
		if tagName == fieldType.Tag.Get("jwt") {
			field := objValElem.Field(i)
			return &field
		}
	}

	return nil
}

// decodeToObjOrFieldWithTag decodes the buf into obj's field having the
// specified jwt tagName. If the provided obj's has the same type as
// defaultObj, then the obj is set to the defaultObj, otherwise an attempt is
// made to json.Decode the buf into obj.
func decodeToObjOrFieldWithTag(buf []byte, obj interface{}, tagName string, defaultObj interface{}) error {
	// reflect values
	objValElem := reflect.ValueOf(obj).Elem()
	defaultObjValElem := reflect.ValueOf(defaultObj).Elem()

	// first check type, if same type, then set
	if objValElem.Type() == defaultObjValElem.Type() {
		objValElem.Set(defaultObjValElem)
		return nil
	}

	// get field with specified jwt tagName (if any)
	fieldVal := getFieldWithTag(obj, tagName)
	if fieldVal != nil {
		// check field type and defaultObj type, if same, set
		if fieldVal.Type() == defaultObjValElem.Type() {
			fieldVal.Set(defaultObjValElem)
			return nil
		}

		// otherwise, assign obj address of field
		obj = fieldVal.Addr().Interface()
	}

	// decode json
	d := json.NewDecoder(bytes.NewBuffer(buf))
	d.UseNumber()
	return d.Decode(obj)
}

// peekField looks at an undecoded JWT, JSON decoding the data at pos, and
// returning the specified field's value as string.
//
// If the fieldName is not present, then an error will be returned.
func peekField(buf []byte, fieldName string, pos int) (string, error) {
	var err error

	// split token
	ut := UnverifiedToken{}
	err = DecodeUnverifiedToken(buf, &ut)
	if err != nil {
		return "", err
	}

	// determine position decode
	var typ string
	var b []byte
	switch pos {
	case 0:
		typ = "header"
		b = ut.Header
	case 1:
		typ = "payload"
		b = ut.Payload

	default:
		return "", fmt.Errorf("invalid field %d", pos)
	}

	// b64 decode
	dec, err := b64.DecodeString(string(b))
	if err != nil {
		return "", fmt.Errorf("could not decode token %s", typ)
	}

	// json decode
	m := make(map[string]interface{})
	err = json.Unmarshal(dec, &m)
	if err != nil {
		return "", err
	}

	if val, ok := m[fieldName]; ok {
		return fmt.Sprintf("%v", val), nil
	}

	return "", fmt.Errorf("token %s field %s not present or invalid", typ, fieldName)
}
