package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyWithOutAuthHeader(t *testing.T) {
	apiKey, err := GetAPIKey(http.Header{})

	if err.Error() != "no authorization header included" {
		t.Errorf("expected: apiKey: \"\", err: no authorization header included, got: apiKey: %v, err: %v", apiKey, err)
	}
}

func TestGetAPIKeyWithMalformedAuthHeader(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "ApiKeyab1cd2ef3gh4ij5kl6mn7op8qr9st10uv11wx12yz13")

	apiKey, err := GetAPIKey(header)

	if err == nil {
		t.Errorf("expected: apiKey: \"\", err: malformed authorization header, got: %v, %v", apiKey, err)
	}

	header.Set("Authorization", "apikey ab1cd2ef3gh4ij5kl6mn7op8qr9st10uv11wx12yz13")

	_, err = GetAPIKey(header)

	if err == nil {
		t.Errorf("expected: apiKey: \"\", err: malformed authorization header, got: %v, %v", apiKey, err)
	}
}

func TestGetAPIKeyWithValidAuthHeader(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "ApiKeyab1cd2ef3gh4ij5kl6mn7op8qr9st10uv11wx12yz13")

	apiKey, err := GetAPIKey(header)

	if apiKey != "ab1cd2ef3gh4ij5kl6mn7op8qr9st10uv11wx12yz13" {
		t.Errorf("expected: apiKey: ab1cd2ef3gh4ij5kl6mn7op8qr9st10uv11wx12yz13, err: nil, got: apiKey: %v, err: %v", apiKey, err)
	}
}
