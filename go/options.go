package sigil

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
)

type tokenConfig struct {
	alg   string
	enc   string
	kid   string
	typ   string
	extra map[string]any
}

func newTokenConfig(key *Key) *tokenConfig {
	return &tokenConfig{kid: key.kid, typ: "JWT", extra: map[string]any{}}
}

// SignOption configures Sign.
type SignOption interface {
	applySign(*tokenConfig)
}

// EncryptOption configures Encrypt.
type EncryptOption interface {
	applyEncrypt(*tokenConfig)
}

type signOption func(*tokenConfig)

func (o signOption) applySign(c *tokenConfig) { o(c) }

type encryptOption func(*tokenConfig)

func (o encryptOption) applyEncrypt(c *tokenConfig) { o(c) }

// HeaderOption sets a header parameter. It is accepted by both Sign and Encrypt.
type HeaderOption func(*tokenConfig)

func (o HeaderOption) applySign(c *tokenConfig)    { o(c) }
func (o HeaderOption) applyEncrypt(c *tokenConfig) { o(c) }

// WithAlgorithm sets the JWS algorithm. It defaults to the key's algorithm,
// or to the natural algorithm for the key type.
func WithAlgorithm(alg string) SignOption {
	return signOption(func(c *tokenConfig) { c.alg = alg })
}

// WithKeyAlgorithm sets the JWE key management algorithm.
func WithKeyAlgorithm(alg string) EncryptOption {
	return encryptOption(func(c *tokenConfig) { c.alg = alg })
}

// WithEncryption sets the JWE content encryption algorithm. It defaults to A256GCM.
func WithEncryption(enc string) EncryptOption {
	return encryptOption(func(c *tokenConfig) { c.enc = enc })
}

// WithKeyID sets the kid header. It defaults to the key's ID; an empty string omits it.
func WithKeyID(kid string) HeaderOption {
	return func(c *tokenConfig) { c.kid = kid }
}

// WithType sets the typ header. It defaults to "JWT"; an empty string omits it.
func WithType(typ string) HeaderOption {
	return func(c *tokenConfig) { c.typ = typ }
}

// WithHeader adds a header parameter, and may override typ and kid.
// The alg, enc, zip and crit parameters cannot be set this way and are ignored.
func WithHeader(name string, value any) HeaderOption {
	return func(c *tokenConfig) {
		switch name {
		case "alg", "enc", "zip", "crit":
		default:
			c.extra[name] = value
		}
	}
}

// header encodes the protected header with alg, enc, typ and kid first and
// the extra parameters after them in name order.
func (c *tokenConfig) header(alg, enc string, extra map[string]any) ([]byte, error) {
	type member struct {
		name  string
		value any
	}
	members := []member{{"alg", alg}}
	if enc != "" {
		members = append(members, member{"enc", enc})
	}
	typ, kid := any(c.typ), any(c.kid)
	if v, ok := extra["typ"]; ok {
		typ = v
	}
	if v, ok := extra["kid"]; ok {
		kid = v
	}
	if typ != "" {
		members = append(members, member{"typ", typ})
	}
	if kid != "" {
		members = append(members, member{"kid", kid})
	}
	for _, name := range slices.Sorted(maps.Keys(extra)) {
		if name != "typ" && name != "kid" {
			members = append(members, member{name, extra[name]})
		}
	}

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, _ := json.Marshal(m.name)
		value, err := json.Marshal(m.value)
		if err != nil {
			return nil, fail(ErrMalformed, "header parameter "+m.name+" is not JSON")
		}
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
