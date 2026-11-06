package sigil_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	sigil "github.com/hostfog/sigil/go"
)

func TestClaimRules(t *testing.T) {
	key := sigil.NewSecret(secret(32))
	now := sigil.Now(time.Unix(1000, 0))
	tests := []struct {
		name   string
		claims string
		opts   []sigil.VerifyOption
		want   *sigil.Error
		claim  string
	}{
		{"exp in future", `{"exp":1001}`, nil, nil, ""},
		{"exp now", `{"exp":1000}`, nil, sigil.ErrExpired, "exp"},
		{"exp fractional", `{"exp":1000.5}`, nil, nil, ""},
		{"exp within leeway", `{"exp":990}`, []sigil.VerifyOption{sigil.Leeway(11 * time.Second)}, nil, ""},
		{"exp at leeway", `{"exp":990}`, []sigil.VerifyOption{sigil.Leeway(10 * time.Second)}, sigil.ErrExpired, "exp"},
		{"exp not a number", `{"exp":"1001"}`, nil, sigil.ErrInvalidClaim, "exp"},
		{"nbf in future", `{"nbf":1001}`, nil, sigil.ErrNotYetValid, "nbf"},
		{"nbf now", `{"nbf":1000}`, nil, nil, ""},
		{"nbf within leeway", `{"nbf":1001}`, []sigil.VerifyOption{sigil.Leeway(time.Second)}, nil, ""},
		{"nbf not a number", `{"nbf":true}`, nil, sigil.ErrInvalidClaim, "nbf"},
		{"iat in future", `{"iat":1001}`, nil, sigil.ErrInvalidClaim, "iat"},
		{"iat within leeway", `{"iat":1001}`, []sigil.VerifyOption{sigil.Leeway(time.Second)}, nil, ""},
		{"iat not a number", `{"iat":null}`, nil, sigil.ErrInvalidClaim, "iat"},
		{"max age ok", `{"iat":940}`, []sigil.VerifyOption{sigil.MaxAge(time.Minute)}, nil, ""},
		{"max age exceeded", `{"iat":939}`, []sigil.VerifyOption{sigil.MaxAge(time.Minute)}, sigil.ErrExpired, "iat"},
		{"max age with leeway", `{"iat":939}`, []sigil.VerifyOption{sigil.MaxAge(time.Minute), sigil.Leeway(time.Second)}, nil, ""},
		{"max age without iat", `{}`, []sigil.VerifyOption{sigil.MaxAge(time.Minute)}, sigil.ErrInvalidClaim, "iat"},
		{"issuer", `{"iss":"b"}`, []sigil.VerifyOption{sigil.Issuer("a", "b")}, nil, ""},
		{"issuer mismatch", `{"iss":"c"}`, []sigil.VerifyOption{sigil.Issuer("a", "b")}, sigil.ErrInvalidClaim, "iss"},
		{"issuer missing", `{}`, []sigil.VerifyOption{sigil.Issuer("a")}, sigil.ErrInvalidClaim, "iss"},
		{"audience string", `{"aud":"api"}`, []sigil.VerifyOption{sigil.Audience("api")}, nil, ""},
		{"audience array", `{"aud":["web","api"]}`, []sigil.VerifyOption{sigil.Audience("x", "api")}, nil, ""},
		{"audience mismatch", `{"aud":["web"]}`, []sigil.VerifyOption{sigil.Audience("api")}, sigil.ErrInvalidClaim, "aud"},
		{"audience missing", `{}`, []sigil.VerifyOption{sigil.Audience("api")}, sigil.ErrInvalidClaim, "aud"},
		{"subject", `{"sub":"u1"}`, []sigil.VerifyOption{sigil.Subject("u1")}, nil, ""},
		{"subject mismatch", `{"sub":"u2"}`, []sigil.VerifyOption{sigil.Subject("u1")}, sigil.ErrInvalidClaim, "sub"},
		{"type", `{}`, []sigil.VerifyOption{sigil.Type("jwt")}, nil, ""},
		{"type mismatch", `{}`, []sigil.VerifyOption{sigil.Type("at+jwt")}, sigil.ErrInvalidClaim, "typ"},
		{"required", `{"jti":"1"}`, []sigil.VerifyOption{sigil.Required("jti")}, nil, ""},
		{"required missing", `{}`, []sigil.VerifyOption{sigil.Required("jti")}, sigil.ErrInvalidClaim, "jti"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := sigil.Sign(json.RawMessage(tt.claims), key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = sigil.Verify(token, key, append(tt.opts, now)...)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			wantErr(t, err, tt.want)
			var e *sigil.Error
			if !errors.As(err, &e) || e.Claim != tt.claim {
				t.Fatalf("claim = %q, want %q", e.Claim, tt.claim)
			}
		})
	}
}

func TestLargeNumbersRoundTrip(t *testing.T) {
	key := sigil.NewSecret(secret(32))
	token, err := sigil.Sign(json.RawMessage(`{"big":12345678901234567890,"exp":99999999999}`), key)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sigil.Verify(token, key)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Claims["big"] != json.Number("12345678901234567890") {
		t.Fatalf("big = %#v", tok.Claims["big"])
	}
	var out struct {
		Big uint64 `json:"big"`
	}
	if err := tok.Bind(&out); err != nil || out.Big != 12345678901234567890 {
		t.Fatalf("Bind = %d, %v", out.Big, err)
	}
}

func TestErrorCodes(t *testing.T) {
	sentinels := map[*sigil.Error]string{
		sigil.ErrMalformed:        "malformed",
		sigil.ErrUnsupportedAlg:   "unsupported_alg",
		sigil.ErrInvalidKey:       "invalid_key",
		sigil.ErrKeyNotFound:      "key_not_found",
		sigil.ErrInvalidSignature: "invalid_signature",
		sigil.ErrExpired:          "expired",
		sigil.ErrNotYetValid:      "not_yet_valid",
		sigil.ErrInvalidClaim:     "invalid_claim",
	}
	for err, code := range sentinels {
		if err.Code != code {
			t.Errorf("%v has code %q, want %q", err, err.Code, code)
		}
	}
	if errors.Is(sigil.ErrExpired, sigil.ErrNotYetValid) {
		t.Error("distinct codes must not match")
	}
}
