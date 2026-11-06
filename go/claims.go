package sigil

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// VerifyOption configures Verify and Decrypt.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	algorithms []string
	issuers    []string
	audiences  []string
	subject    string
	typ        string
	leeway     time.Duration
	maxAge     time.Duration
	required   []string
	now        time.Time
}

func newVerifyConfig(opts []VerifyOption) *verifyConfig {
	c := &verifyConfig{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Algorithms limits the accepted alg values. By default the key's algorithm
// is accepted, or every algorithm valid for the key type.
func Algorithms(algs ...string) VerifyOption {
	return func(c *verifyConfig) { c.algorithms = algs }
}

// Issuer requires iss to equal one of the given values.
func Issuer(iss ...string) VerifyOption {
	return func(c *verifyConfig) { c.issuers = iss }
}

// Audience requires aud to contain one of the given values.
func Audience(aud ...string) VerifyOption {
	return func(c *verifyConfig) { c.audiences = aud }
}

// Subject requires sub to equal sub.
func Subject(sub string) VerifyOption {
	return func(c *verifyConfig) { c.subject = sub }
}

// Type requires the typ header to equal typ, ignoring case.
func Type(typ string) VerifyOption {
	return func(c *verifyConfig) { c.typ = typ }
}

// Leeway allows for clock skew when checking exp, nbf and iat.
func Leeway(d time.Duration) VerifyOption {
	return func(c *verifyConfig) { c.leeway = d }
}

// MaxAge requires iat and rejects tokens issued more than d ago.
func MaxAge(d time.Duration) VerifyOption {
	return func(c *verifyConfig) { c.maxAge = d }
}

// Required lists claims that must be present.
func Required(claims ...string) VerifyOption {
	return func(c *verifyConfig) { c.required = claims }
}

// Now overrides the current time.
func Now(t time.Time) VerifyOption {
	return func(c *verifyConfig) { c.now = t }
}

func (c *verifyConfig) validate(header, claims map[string]any) error {
	exp, hasExp, err := numericClaim(claims, "exp")
	if err != nil {
		return err
	}
	nbf, hasNbf, err := numericClaim(claims, "nbf")
	if err != nil {
		return err
	}
	iat, hasIat, err := numericClaim(claims, "iat")
	if err != nil {
		return err
	}
	for _, name := range c.required {
		if _, ok := claims[name]; !ok {
			return claimError(ErrInvalidClaim, name, "missing")
		}
	}

	now := c.now
	if now.IsZero() {
		now = time.Now()
	}
	t := float64(now.Unix())
	leeway := c.leeway.Seconds()

	if hasExp && t >= exp+leeway {
		return claimError(ErrExpired, "exp", "token has expired")
	}
	if hasNbf && t < nbf-leeway {
		return claimError(ErrNotYetValid, "nbf", "token is not valid yet")
	}
	if hasIat && iat > t+leeway {
		return claimError(ErrInvalidClaim, "iat", "issued in the future")
	}
	if c.maxAge > 0 {
		if !hasIat {
			return claimError(ErrInvalidClaim, "iat", "missing")
		}
		if t-iat > c.maxAge.Seconds()+leeway {
			return claimError(ErrExpired, "iat", "token is too old")
		}
	}

	if len(c.issuers) > 0 {
		iss, ok := claims["iss"].(string)
		if !ok || !slices.Contains(c.issuers, iss) {
			return claimError(ErrInvalidClaim, "iss", "unexpected issuer")
		}
	}
	if len(c.audiences) > 0 && !containsAudience(claims["aud"], c.audiences) {
		return claimError(ErrInvalidClaim, "aud", "unexpected audience")
	}
	if c.subject != "" {
		if sub, ok := claims["sub"].(string); !ok || sub != c.subject {
			return claimError(ErrInvalidClaim, "sub", "unexpected subject")
		}
	}
	if c.typ != "" {
		if typ, ok := header["typ"].(string); !ok || !strings.EqualFold(typ, c.typ) {
			return claimError(ErrInvalidClaim, "typ", "unexpected token type")
		}
	}
	return nil
}

func numericClaim(claims map[string]any, name string) (float64, bool, error) {
	v, ok := claims[name]
	if !ok {
		return 0, false, nil
	}
	if n, ok := v.(json.Number); ok {
		if f, err := n.Float64(); err == nil {
			return f, true, nil
		}
	}
	return 0, false, claimError(ErrInvalidClaim, name, "must be a number")
}

func containsAudience(aud any, want []string) bool {
	switch aud := aud.(type) {
	case string:
		return slices.Contains(want, aud)
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && slices.Contains(want, s) {
				return true
			}
		}
	}
	return false
}
