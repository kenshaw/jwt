package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
//
// loadKeysFromPEM will panic if an error is encountered when calling pem.Load.
func loadKeysFromPEM(pem pemutil.PEM) pemutil.Store {
	// attempt to load crypto primitives
	store := pemutil.Store{}
	err := pem.Load(store)
	if err != nil {
		panic(err)
	}

	return store
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
	var err error

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
	err = json.Unmarshal(buf, obj)
	if err != nil {
		return err
	}

	return nil
}
