package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClaimsMarshalUnmarshal(t *testing.T) {
	tm := time.Now().Add(14 * time.Hour)
	tm = tm.Add(time.Duration(-tm.Nanosecond()))

	expr := ClaimsTime(tm)
	c := Claims{Issuer: "issuer", Expiration: &expr}

	buf, err := json.Marshal(&c)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	c0 := Claims{}
	err = json.Unmarshal(buf, &c0)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if expr != *c0.Expiration {
		t.Errorf("expr and c0.Expiration should equal -- %v / %v", expr, c0.Expiration)
	}

	if "issuer" != c0.Issuer {
		t.Errorf("c0.Issuer should be 'issuer'")
	}

	c1 := Claims{}
	err = json.Unmarshal([]byte(`{ "nbf": [] }`), &c1)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}
