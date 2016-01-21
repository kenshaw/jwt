// Package jwt provides a simplified and secure API for encoding, decoding and
// verifying JSON Web Tokens (JWT).
//
// It's API is designed to be instantly familiar to users of the standard json
// package.
//
// see: https://jwt.io/
package jwt

import (
	"bytes"
	"encoding/json"
	"reflect"
)

var (
	// tokenSep is the token separator.
	tokenSep = []byte{'.'}
)

// Decode decodes a JWT, storing values in obj and verifying the signature.
func Decode(alg Algorithm, signer Signer, buf []byte, obj interface{}) error {
	var err error

	// split token
	ut := UnverifiedToken{}
	err = DecodeUnverifiedToken(buf, &ut)
	if err != nil {
		return err
	}

	// verify signature
	sig, err := signer.Verify(buf[:len(ut.Header)+len(tokenSep)+len(ut.Payload)], ut.Signature)
	if err != nil {
		return ErrInvalidSignature
	}

	// b64 decode header
	headerBuf, err := b64.DecodeString(string(ut.Header))
	if err != nil {
		return err
	}

	// json decode header
	header := Header{}
	err = json.Unmarshal(headerBuf, &header)
	if err != nil {
		return err
	}

	// verify alg matches header algorithm
	if alg != header.Algorithm {
		return ErrInvalidAlgorithm
	}

	// set header in the provided obj
	err = decodeToObjOrFieldWithTag(headerBuf, obj, "header", &header)
	if err != nil {
		return err
	}

	// b64 decode payload
	payloadBuf, err := b64.DecodeString(string(ut.Payload))
	if err != nil {
		return err
	}

	// json decode payload
	payload := Claims{}
	err = json.Unmarshal(payloadBuf, &payload)
	if err != nil {
		return err
	}

	// set payload in the provided obj
	err = decodeToObjOrFieldWithTag(payloadBuf, obj, "payload", &payload)
	if err != nil {
		return err
	}

	// set sig in the provided obj
	field := getFieldWithTag(obj, "signature")
	if field != nil {
		field.Set(reflect.ValueOf(sig))
	}

	return nil
}

// Encode encodes a obj as the claim in a Token using the Algorithm and Signer.
func Encode(alg Algorithm, signer Signer, obj interface{}) ([]byte, error) {
	var err error
	var headerObj, payloadObj interface{}

	// determine what to encode
	switch val := obj.(type) {
	case *Token:
		headerObj = val.Header
		payloadObj = val.Payload

	default:
		headerObj = alg.Header()
		payloadObj = val
	}

	// json encode header
	header, err := json.Marshal(headerObj)
	if err != nil {
		return nil, err
	}

	// b64 encode playload
	headerEnc := make([]byte, b64.EncodedLen(len(header)))
	b64.Encode(headerEnc, header)

	// json encode payload
	payload, err := json.Marshal(payloadObj)
	if err != nil {
		return nil, err
	}

	// b64 encode playload
	payloadEnc := make([]byte, b64.EncodedLen(len(payload)))
	b64.Encode(payloadEnc, payload)

	// allocate result
	var buf bytes.Buffer

	// add header
	_, err = buf.Write(headerEnc)
	if err != nil {
		return nil, err
	}

	// add 1st separator
	_, err = buf.Write(tokenSep)
	if err != nil {
		return nil, err
	}

	// add payload
	_, err = buf.Write(payloadEnc)
	if err != nil {
		return nil, err
	}

	// sign
	sig, err := signer.Sign(buf.Bytes())
	if err != nil {
		return nil, err
	}

	// add 2nd separator
	_, err = buf.Write(tokenSep)
	if err != nil {
		return nil, err
	}

	// add sig
	_, err = buf.Write(sig)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
