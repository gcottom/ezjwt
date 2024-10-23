package ezjwt

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type JWT struct {
	token     string
	payload   []byte
	claims    map[string]any
	expiresAt int64
}

// Decode decodes a JWT token and returns a JWT struct
func Decode(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %w", err)
	}
	jwt := &JWT{payload: payload, token: token}
	if err := json.Unmarshal(payload, &jwt.claims); err != nil {
		return nil, fmt.Errorf("error unmarshalling payload: %w", err)
	}
	exp, ok := jwt.claims["exp"].(float64)
	if !ok {
		return nil, errors.New("exp not found")
	}
	jwt.expiresAt = int64(exp)
	return jwt, nil
}

// IsExpired checks if the token is expired
func (jwt *JWT) IsExpired() bool {
	return jwt.expiresAt < time.Now().Unix()
}

// Claims returns the claims of the token as a map[string]any. Note that when claims are unmarshalled into
// the map that integer values are converted to float64 and when using those values from the map, you should
// type assert them to float64 first, then convert them to int64 if needed.
func (jwt *JWT) Claims() map[string]any {
	return jwt.claims
}

// UnmarshalClaims unmarshals the claims of the token into the provided struct v, which should be a pointer.
// Returns the usual json unmarshalling errors.
func (jwt *JWT) UnmarshalClaims(v any) error {
	return json.Unmarshal(jwt.payload, v)
}

// IsValid takes a token and a string secret, *rsa.PrivateKey, or *ecdsa.PrivateKey. IsValid checks
// if the token is valid by verifying the signature and expiration. It retuns a boolean indicating if
// the token is valid and an error if any. If the token is invalid, the error message will provide more
// information about the reason.
func IsValid[T string | *rsa.PrivateKey | *ecdsa.PrivateKey](token string, secret T) (bool, error) {
	jwt, err := Decode(token)
	if err != nil {
		return false, fmt.Errorf("error decoding token: %w", err)
	}
	if jwt.IsExpired() {
		return false, errors.New("token expired")
	}
	parts := strings.Split(jwt.token, ".")
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("error decoding header: %w", err)
	}
	var headerMap map[string]any
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return false, fmt.Errorf("error unmarshalling header: %w", err)
	}
	tAlg, ok := headerMap["alg"].(string)
	if !ok {
		return false, errors.New("alg not found")
	}

	var data []byte
	data = append(data, parts[0]...)
	data = append(data, '.')
	data = append(data, parts[1]...)
	genSig, err := generateSignature(string(data), secret, Algorithm(tAlg))
	if err != nil {
		return false, fmt.Errorf("error generating verification signature: %w", err)
	}
	expected, err := base64.RawURLEncoding.DecodeString(genSig)
	if err != nil {
		return false, fmt.Errorf("error decoding verifcation signature: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("error decoding signature: %w", err)
	}
	if !hmac.Equal(signature, expected) {
		return false, errors.New("invalid signature")
	}
	return true, nil
}
