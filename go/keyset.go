package sigil

import (
	"encoding/json"
	"slices"
)

// KeySource supplies keys to Verify and Decrypt. It is implemented by *Key and *KeySet.
type KeySource interface {
	candidates(kid, alg string, private bool) ([]*Key, error)
	allows(alg string) bool
}

// KeySet is a set of keys, such as a JWKS. The zero value is an empty set.
type KeySet struct {
	keys []*Key
}

// ParseJWKS parses a JWK Set. Entries with an unknown kty or curve are skipped.
func ParseJWKS(data []byte) (*KeySet, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fail(ErrInvalidKey, "invalid JWKS")
	}
	s := &KeySet{}
	for _, raw := range doc.Keys {
		var j jwk
		if err := json.Unmarshal(raw, &j); err != nil {
			return nil, errBadJWK
		}
		if !supported(&j) {
			continue
		}
		k, err := j.key()
		if err != nil {
			return nil, err
		}
		s.Add(k)
	}
	return s, nil
}

func supported(j *jwk) bool {
	switch j.Kty {
	case "oct", "RSA":
		return true
	case "EC":
		_, ok := ecCurves[j.Crv]
		return ok
	case "OKP":
		return j.Crv == "Ed25519" || j.Crv == "X25519"
	}
	return false
}

// Add appends k to the set.
func (s *KeySet) Add(k *Key) {
	s.keys = append(s.keys, k)
}

// Get returns the key with the given ID, or nil.
func (s *KeySet) Get(kid string) *Key {
	for _, k := range s.keys {
		if k.kid == kid {
			return k
		}
	}
	return nil
}

// Keys returns the keys in the set.
func (s *KeySet) Keys() []*Key {
	return slices.Clone(s.keys)
}

// JSON returns the set as a JWKS document. Without includePrivate, only
// public keys are written and symmetric keys are left out.
func (s *KeySet) JSON(includePrivate bool) ([]byte, error) {
	doc := struct {
		Keys []*jwk `json:"keys"`
	}{Keys: []*jwk{}}
	for _, k := range s.keys {
		if k.kty == "oct" && !includePrivate {
			continue
		}
		doc.Keys = append(doc.Keys, k.jwk(includePrivate))
	}
	return json.Marshal(doc)
}

func (s *KeySet) candidates(kid, alg string, private bool) ([]*Key, error) {
	if kid != "" {
		k := s.Get(kid)
		if k == nil {
			return nil, fail(ErrKeyNotFound, "no key with the token's kid")
		}
		return k.candidates(kid, alg, private)
	}
	var keys []*Key
	for _, k := range s.keys {
		if k.check(alg, private) == nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, fail(ErrKeyNotFound, "no key for "+alg)
	}
	return keys, nil
}

func (s *KeySet) allows(alg string) bool {
	return slices.ContainsFunc(s.keys, func(k *Key) bool { return k.allows(alg) })
}
