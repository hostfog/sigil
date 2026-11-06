package sigil_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	sigil "github.com/hostfog/sigil/go"
)

var interopNow = time.Unix(1800000000, 0)

type interopCase struct {
	Kind, Alg, Enc, Key string
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testKeys(t *testing.T) *sigil.KeySet {
	t.Helper()
	set, err := sigil.ParseJWKS(readTestdata(t, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func testKey(t *testing.T, kid string) *sigil.Key {
	t.Helper()
	k := testKeys(t).Get(kid)
	if k == nil {
		t.Fatalf("no test key %q", kid)
	}
	return k
}

func interopFixture(t *testing.T) (map[string]any, []interopCase) {
	t.Helper()
	var doc struct {
		Claims map[string]any
		Cases  []interopCase
	}
	dec := json.NewDecoder(bytes.NewReader(readTestdata(t, "interop.json")))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.Claims, doc.Cases
}

func wantErr(t *testing.T, err error, want *sigil.Error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want code %s", err, want.Code)
	}
}

func sameJSON(t *testing.T, got, want any) {
	t.Helper()
	norm := func(v any) any {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var out any
		json.Unmarshal(b, &out)
		return out
	}
	if g, w := norm(got), norm(want); !reflect.DeepEqual(g, w) {
		t.Fatalf("got %v, want %v", g, w)
	}
}

// forgeHS256 builds a token with an arbitrary header, signed with secret.
func forgeHS256(header, payload string, secret []byte) string {
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + enc.EncodeToString(mac.Sum(nil))
}

func secret(n int) []byte {
	return bytes.Repeat([]byte{'k'}, n)
}
