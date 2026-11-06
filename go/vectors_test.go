package sigil_test

import (
	"encoding/json"
	"testing"
	"time"

	sigil "github.com/hostfog/sigil/go"
)

func TestRFC7515AppendixA1(t *testing.T) {
	var v struct {
		RFC7515A1 struct {
			Key    json.RawMessage `json:"key"`
			Token  string          `json:"token"`
			Now    int64           `json:"now"`
			Claims map[string]any  `json:"claims"`
		} `json:"rfc7515_a1"`
	}
	if err := json.Unmarshal(readTestdata(t, "vectors.json"), &v); err != nil {
		t.Fatal(err)
	}
	vec := v.RFC7515A1
	key, err := sigil.ParseJWK(vec.Key)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sigil.Verify(vec.Token, key, sigil.Now(time.Unix(vec.Now, 0)))
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, tok.Claims, vec.Claims)

	_, err = sigil.Verify(vec.Token, key)
	wantErr(t, err, sigil.ErrExpired)
}

func TestRFC7638Thumbprint(t *testing.T) {
	var v struct {
		Vec struct {
			Key        json.RawMessage `json:"key"`
			Thumbprint string          `json:"thumbprint"`
		} `json:"rfc7638_thumbprint"`
	}
	if err := json.Unmarshal(readTestdata(t, "vectors.json"), &v); err != nil {
		t.Fatal(err)
	}
	key, err := sigil.ParseJWK(v.Vec.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got := key.Thumbprint(); got != v.Vec.Thumbprint {
		t.Fatalf("thumbprint = %s, want %s", got, v.Vec.Thumbprint)
	}
}
