package sigil_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	sigil "github.com/hostfog/sigil/go"
)

func issue(t *testing.T, c interopCase, claims map[string]any, key *sigil.Key) string {
	t.Helper()
	var token string
	var err error
	if c.Kind == "jws" {
		token, err = sigil.Sign(claims, key, sigil.WithAlgorithm(c.Alg))
	} else {
		if pub := key.Public(); pub != nil {
			key = pub
		}
		token, err = sigil.Encrypt(claims, key, sigil.WithKeyAlgorithm(c.Alg), sigil.WithEncryption(c.Enc))
	}
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func open(token string, c interopCase, keys sigil.KeySource) (*sigil.Token, error) {
	opts := []sigil.VerifyOption{
		sigil.Algorithms(c.Alg), sigil.Issuer("sigil"), sigil.Audience("all"), sigil.Now(interopNow),
	}
	if c.Kind == "jws" {
		return sigil.Verify(token, keys, opts...)
	}
	return sigil.Decrypt(token, keys, opts...)
}

func TestRoundTrip(t *testing.T) {
	claims, cases := interopFixture(t)
	keys := testKeys(t)
	for _, c := range cases {
		t.Run(c.Kind+"/"+c.Alg+"/"+c.Enc+"/"+c.Key, func(t *testing.T) {
			key := keys.Get(c.Key)
			token := issue(t, c, claims, key)

			tok, err := open(token, c, key)
			if err != nil {
				t.Fatal(err)
			}
			sameJSON(t, tok.Claims, claims)
			if n, ok := tok.Claims["n"].(json.Number); !ok || n != "42" {
				t.Fatalf("n = %#v, want json.Number 42", tok.Claims["n"])
			}
			if tok.Header["alg"] != c.Alg || tok.Header["kid"] != c.Key || tok.Header["typ"] != "JWT" {
				t.Fatalf("header = %v", tok.Header)
			}

			if _, err := open(token, c, keys); err != nil {
				t.Fatalf("with key set: %v", err)
			}
		})
	}
}

func tamper(token string, part int) string {
	parts := strings.Split(token, ".")
	b := []byte(parts[part])
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	parts[part] = string(b)
	return strings.Join(parts, ".")
}

func TestTampered(t *testing.T) {
	claims, cases := interopFixture(t)
	keys := testKeys(t)
	for _, c := range cases {
		t.Run(c.Kind+"/"+c.Alg+"/"+c.Enc+"/"+c.Key, func(t *testing.T) {
			key := keys.Get(c.Key)
			token := issue(t, c, claims, key)

			parts := []int{2}
			if c.Kind == "jwe" {
				parts = []int{2, 3, 4}
				if c.Alg != sigil.Dir && c.Alg != sigil.ECDHES {
					parts = append(parts, 1)
				}
			} else {
				segs := strings.Split(token, ".")
				segs[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"sigil","aud":"all","admin":true}`))
				_, err := open(strings.Join(segs, "."), c, key)
				wantErr(t, err, sigil.ErrInvalidSignature)
			}
			for _, part := range parts {
				_, err := open(tamper(token, part), c, key)
				wantErr(t, err, sigil.ErrInvalidSignature)
			}
		})
	}
}
