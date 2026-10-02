package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const signingKey = "sup3r-s3cr3t-k3y-d0nt-sh4r3"

var header = map[string]string{
	"alg": "HS256",
	"typ": "JWT",
}

// Tests for Token are located in jwt/jwt_test.go.
//
// Changelog:
//   - v0.1: added Token with Subject, IssuedAt and ExpiresAt. IssuedAt was int.
//   - v0.2: added CustomClaims.
//   - v0.3: changed IssuedAt from int to int64.
//   - v0.4: changed ExpiresAt from int to int64 to match IssuedAt.
type Token struct {
	Subject      string
	IssuedAt     int64
	ExpiresAt    int64
	CustomClaims map[string]interface{}
}

func Encode(sub string, iat int64, exp int64, customClaims map[string]interface{}) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	claims := map[string]interface{}{
		"sub": sub,
		"iat": iat,
		"exp": exp,
	}
	for k, v := range customClaims {
		claims[k] = v
	}

	// JSON (JavaScript Object Notation) is a lightweight, text-based data
	// interchange format. It was derived from JavaScript but is language
	// independent, and it is used almost everywhere on the web today. A JSON
	// document is built from objects (key/value pairs wrapped in curly braces),
	// arrays (ordered lists wrapped in square brackets), strings, numbers,
	// booleans and null. Keys in an object are always strings.
	//
	// json.Marshal from the standard library encoding/json package takes any
	// Go value and returns its JSON encoding as a byte slice. It walks the
	// value using reflection: structs become objects (using json struct tags
	// for the key names if present), slices and arrays become arrays, maps
	// with string keys become objects, and primitive types become the
	// matching JSON primitives. Map keys are sorted, so the output is
	// deterministic.
	//
	// json.Marshal returns an error if the value contains something that
	// cannot be represented in JSON, for example a channel, a function, or a
	// complex number. That is why we check err below.
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	unsigned := encodeSegment(headerJSON) + "." + encodeSegment(payloadJSON)
	return unsigned + "." + encodeSegment(sign(unsigned)), nil
}

func Decode(token string) (*Token, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var h map[string]string
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	if h["alg"] != "HS256" || h["typ"] != "JWT" {
		return nil, errors.New("unsupported token header")
	}

	signature, err := decodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	if !hmac.Equal(signature, sign(parts[0]+"."+parts[1])) {
		return nil, errors.New("invalid signature")
	}

	payloadJSON, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	t := &Token{CustomClaims: map[string]interface{}{}}
	for k, v := range claims {
		switch k {
		case "sub":
			t.Subject, _ = v.(string)
		case "iat":
			if f, ok := v.(float64); ok {
				t.IssuedAt = int64(f)
			}
		case "exp":
			if f, ok := v.(float64); ok {
				t.ExpiresAt = int64(f)
			}
		default:
			t.CustomClaims[k] = v
		}
	}

	if time.Now().Unix() > t.ExpiresAt {
		return nil, errors.New("token expired")
	}

	return t, nil
}

func sign(data string) []byte {
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
