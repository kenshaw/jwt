package jwt

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func enc(v string) string {
	return b64.EncodeToString([]byte(v))
}

type sigger struct {
	signer Signer
}

func (s *sigger) sn(v string) string {
	enc, err := s.signer.Sign([]byte(v))
	if err != nil {
		panic(err)
	}
	return v + `.` + string(enc)
}

func TestSignAndVerify(t *testing.T) {
	tests := getTests()
	for i, test := range tests {
		var p PEM

		// load PEM
		algName := test.alg.String()
		switch algName[:2] {
		case "HS":
			p = PEM{"testdata/hmac.pem"}
		case "RS", "PS":
			p = PEM{"testdata/rsa.pem"}
		case "ES":
			p = PEM{"testdata/" + strings.ToLower(algName) + ".pem"}
		}

		// gen signature
		signer := test.alg.New(p)

		// only test valid sigs
		if test.valid {
			// split token
			tok := strings.Split(test.tok, string(tokenSep))
			if len(tok) != 3 {
				t.Errorf("test %d %s token should have 3 parts, got: %d", i, test.alg, len(tok))
				continue
			}

			// grab stuff
			buf := []byte(test.tok[:len(tok[0])+len(tokenSep)+len(tok[1])])

			// sign
			sig, err := signer.Sign(buf)
			if err != nil {
				t.Errorf("test %d %s expected no error, got: %v", i, test.alg, err)
				continue
			}
			if sig == nil || len(sig) == 0 {
				t.Errorf("test %d %s sig should not be nil or empty byte slice", i, test.alg)
				continue
			}

			// byte compare
			algName := test.alg.String()
			if algName[:2] != "PS" && algName[:2] != "ES" && !bytes.Equal([]byte(tok[2]), sig) {
				// ECC/PSS doesn't produce signatures that are bit equal, the
				// RSS & HMAC do
				t.Errorf("test %d %s sig are not equal", i, test.alg)
				continue
			}

			// verify
			dec, err := signer.Verify(buf, sig)
			if err != nil {
				t.Errorf("test %d %s expected no error, got: %v", i, test.alg, err)
				continue
			}
			if len(dec) == 0 {
				t.Errorf("test %d %s should return a non-empty b62 decoded signature", i, test.alg)
				continue
			}
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	signer := PS256.New(PEM{"testdata/rsa.pem"})
	s := &sigger{signer}
	b := &sigger{PS384.New(PEM{"testdata/rsa.pem"})}

	tests := []string{
		``,
		`.`,
		`..`,
		`{}.`,
		`{}..`,
		`{}.{}`,
		`{}.{}.`,
		`{}.{}.xyz`,
		enc(`{}`),
		enc(`{}`) + `.`,
		enc(`{}`) + `.` + enc(`{}`),
		enc(`{}`) + `.` + enc(`{}`) + `.`,
		s.sn(`{}.{}`),
		s.sn(enc(`{}`) + `.{}`),
		s.sn(`{}.` + enc(`{}`)),
		s.sn(enc(`{}`) + `.` + enc(`{}`)),
		s.sn(enc(`{alg:}`) + `.` + enc(`{}`)),
		s.sn(enc(`{alg:""}`) + `.` + enc(`{}`)),
		s.sn(enc(`{"alg":}`) + `.` + enc(`{}`)),
		s.sn(enc(`{"alg":123}`) + `.` + enc(`{}`)),
		s.sn(enc(`{"alg":"ES256"}`) + `.` + enc(`{}`)),
		s.sn(enc(`{"alg":"none"}`) + `.` + enc(`{}`)),
		s.sn(enc(`{"alg":"PS256"}`) + `.{}`),
		s.sn(enc(`{"alg":"PS256"}`) + `.` + enc(``)),
		s.sn(enc(`{"alg":"PS256"}`) + `.` + enc(`{iss:}`)),
		b.sn(enc(`{"alg":"PS256"}`) + `.` + enc(`{"iss":"issuer"}`)),
	}

	for i, test := range tests {
		tok := Token{}
		err := Decode(PS256, signer, []byte(test), &tok)
		if err == nil {
			t.Errorf("test %d expected no error, got: %v", i, err)
		}
	}
}

func TestDecode(t *testing.T) {
	tests := getTests()
	for i, test := range tests {
		var p PEM

		// load PEM
		algName := test.alg.String()
		switch algName[:2] {
		case "HS":
			p = PEM{"testdata/hmac.pem"}
		case "RS", "PS":
			p = PEM{"testdata/rsa.pem"}
		case "ES":
			p = PEM{"testdata/" + strings.ToLower(algName) + ".pem"}
		}

		// gen signature
		signer := test.alg.New(p)

		// split token
		tok := strings.Split(test.tok, string(tokenSep))
		if test.valid && len(tok) != 3 {
			t.Errorf("test %d %s token should have 3 parts, got: %d", i, test.alg, len(tok))
			continue
		}

		t0 := Token{}
		err := signer.Decode([]byte(test.tok), &t0)
		switch {
		case test.valid && err != nil:
			t.Errorf("test %d %s expected no error, got: %v", i, test.alg, err)
			continue
		case !test.valid && err == nil:
			t.Errorf("test %d %s expected err, got nil", i, test.alg)
			continue
		}

		if test.valid {
			if test.alg != t0.Header.Algorithm {
				t.Errorf("test %d %s decoded header should have alg %s", i, test.alg, test.alg)
				continue
			}

			// TODO check that the generated claims match

			if t0.Signature == nil || len(t0.Signature) == 0 {
				t.Errorf("test %d %s decoded signature should not be nil or empty", i, test.alg)
				continue
			}
		}
	}
}

func TestEncode(t *testing.T) {
	tests := getTests()
	for i, test := range tests {
		var p PEM

		// load PEM
		algName := test.alg.String()
		switch algName[:2] {
		case "HS":
			p = PEM{"testdata/hmac.pem"}
		case "RS", "PS":
			p = PEM{"testdata/rsa.pem"}
		case "ES":
			p = PEM{"testdata/" + strings.ToLower(algName) + ".pem"}
		}

		// gen signature
		signer := test.alg.New(p)

		b0, err := signer.Encode(test.exp)
		if err != nil {
			t.Errorf("test %d %s expected no error, got: %v", i, test.alg, err)
			continue
		}
		if b0 == nil || len(b0) == 0 {
			t.Errorf("test %d %s encoded token should not return nil or empty byte slice", i, test.alg)
			continue
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`).Match(b0) {
			t.Errorf("test %d %s token should only have [a-zA-Z0-9_-.] characters", i, test.alg)
			continue
		}

		t0 := bytes.Split(b0, tokenSep)
		if len(t0) != 3 {
			t.Errorf("test %d %s encoded token should have 3 parts", i, test.alg)
			continue
		}

		// check sig
		var e0 bytes.Buffer
		e0.Write(t0[0])
		e0.Write(tokenSep)
		e0.Write(t0[1])

		d0, err := signer.Verify(e0.Bytes(), t0[2])
		if err != nil {
			t.Errorf("test %d %s should verify", i, test.alg)
			continue
		}
		if d0 == nil || len(d0) == 0 {
			t.Errorf("test %d %s d0 should not be nil or empty", i, test.alg)
			continue
		}

		a0, err := b64.DecodeString(string(t0[2]))
		if err != nil {
			t.Errorf("test %d %s t0[2] (signature) should be b64 decodable", i, test.alg)
			continue
		}
		if !bytes.Equal(a0, d0) {
			t.Errorf("test %d %s a0 and d0 should be same value", i, test.alg)
			continue
		}
	}
}

func TestPeekErrors(t *testing.T) {
	tests := []string{
		``,
		`.`,
		`..`,
		`{}..`,
		`{}.{}.`,
		enc(`{}`),
		enc(`{}`) + `.{}.`,
		enc(`{}`) + `.` + enc(`{}`) + `.`,
		enc(`{"alg":}`) + `.` + enc(`{}`) + `.`,
		enc(`{"alg":123}`) + `.` + enc(`{}`) + `.`,
		enc(`{"alg":"ES256"}`) + `.` + enc(`{"iss":}`) + `.`,
		enc(`{"alg":123}`) + `.` + enc(`{"iss":"issuer"}`) + `.`,
		enc(`{"foo":"bar"}`) + `.` + enc(`{"foo":"bar"}`) + `.`,
		enc(`{"alg":"none"}`) + `.` + enc(`{"iss":"issuer"}`) + `.`,
	}

	for i, test := range tests {
		_, _, err := PeekAlgorithmAndIssuer([]byte(test))
		if err == nil {
			t.Errorf("test %d expected error, got nil\n%s\n", i, test)
		}
	}
}

func TestPeek(t *testing.T) {
	test := enc(`{"alg":"ES256"}`) + `.` + enc(`{"iss":"issuer"}`) + `.`
	alg, issuer, err := PeekAlgorithmAndIssuer([]byte(test))
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if "issuer" != issuer {
		t.Errorf("issuer should be 'issuer'")
	}
	if ES256 != alg {
		t.Errorf("alg should be ES256")
	}
}
