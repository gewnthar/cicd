package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKeyBROKEN" {	
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-api-key"},
			},
			expectedKey:   "",
			// We don't have a specific variable for the malformed error in the code you shared,
			// so we expect any error here.
			expectedError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			// 1. Check if we expected a specific error variable (like ErrNoAuthHeaderIncluded)
			if tc.expectedError != nil {
				if err != tc.expectedError {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
				}
				return
			}

			// 2. Handle the case where we expect an error, but not a specific variable (the malformed case)
			// In the table above, I set expectedError to nil for the malformed case to simplify,
			// but we know it should fail. Let's handle that logic specifically:
			if tc.name == "Malformed Authorization Header" {
				if err == nil {
					t.Error("expected an error for malformed header, but got none")
				}
				return
			}

			// 3. Standard success case
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != tc.expectedKey {
				t.Errorf("expected key %v, got %v", tc.expectedKey, key)
			}
		})
	}
}
