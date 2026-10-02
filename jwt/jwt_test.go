package jwt

import (
	"testing"
	"time"
)

func TestEncodeDecode(t *testing.T) {
	now := time.Now().Unix()

	token, err := Encode("user-123", now, now+3600, map[string]interface{}{"role": "admin"})
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Subject != "user-123" {
		t.Errorf("expected subject user-123, got %s", decoded.Subject)
	}
	if decoded.IssuedAt != now {
		t.Errorf("expected iat %d, got %d", now, decoded.IssuedAt)
	}
	if decoded.ExpiresAt != now+3600 {
		t.Errorf("expected exp %d, got %d", now+3600, decoded.ExpiresAt)
	}
	if decoded.CustomClaims["role"] != "admin" {
		t.Errorf("expected role admin, got %v", decoded.CustomClaims["role"])
	}
}

func TestEncodeWithoutCustomClaims(t *testing.T) {
	now := time.Now().Unix()

	token, err := Encode("user-123", now, now+3600, nil)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if len(decoded.CustomClaims) != 0 {
		t.Errorf("expected no custom claims, got %v", decoded.CustomClaims)
	}
}
