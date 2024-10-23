package ezjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
)

func encodeHeader(alg Algorithm) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
}

func encodePayload(payload []byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func generateSignature(data string, secret any, alg Algorithm) (string, error) {
	var signature []byte
	var err error
	switch alg {
	case HS256:
		h := hmac.New(sha256.New, []byte(secret.(string)))
		h.Write([]byte(data))
		signature = h.Sum(nil)
	case HS384:
		h := hmac.New(sha512.New384, []byte(secret.(string)))
		h.Write([]byte(data))
		signature = h.Sum(nil)
	case HS512:
		h := hmac.New(sha512.New, []byte(secret.(string)))
		h.Write([]byte(data))
		signature = h.Sum(nil)
	case RS256:
		privateKey, ok := secret.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		hashed := sha256.Sum256([]byte(data))
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case RS384:
		privateKey, ok := secret.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		hashed := sha512.Sum384([]byte(data))
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA384, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case RS512:
		privateKey, ok := secret.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		hashed := sha512.Sum512([]byte(data))
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case ES256:
		privateKey, ok := secret.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		hashed := sha256.Sum256([]byte(data))
		signature, err = ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case ES384:
		privateKey, ok := secret.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		hashed := sha512.Sum384([]byte(data))
		signature, err = ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case ES512:
		privateKey, ok := secret.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		hashed := sha512.Sum512([]byte(data))
		signature, err = ecdsa.SignASN1(rand.Reader, privateKey, hashed[:])
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case PS256:
		privateKey, ok := secret.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		if privateKey.N.BitLen() < 272 {
			return "", errors.New("error signing data: private key bit length is too small")
		}
		hashed := sha256.Sum256([]byte(data))
		signature, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case PS384:
		privateKey, ok := secret.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		if privateKey.N.BitLen() < 272 {
			return "", errors.New("error signing data: private key bit length is too small")
		}
		hashed := sha512.Sum384([]byte(data))
		signature, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA384, hashed[:], nil)
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	case PS512:
		privateKey, ok := secret.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("invalid private key type")
		}
		if privateKey.N.BitLen() < 272 {
			return "", errors.New("error signing data: private key bit length is too small")
		}
		hashed := sha512.Sum512([]byte(data))
		signature, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, hashed[:], nil)
		if err != nil {
			return "", fmt.Errorf("error signing data: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func marshalClaims(v any) ([]byte, error) {
	if v == nil {
		return nil, errors.New("claims cannot be nil")
	}
	claims, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("error marshalling claims: %w", err)
	}
	var claimsMap map[string]any
	if err := json.Unmarshal(claims, &claimsMap); err != nil {
		return nil, fmt.Errorf("error unmarshalling claims: %w", err)
	}
	exp, ok := claimsMap["exp"]
	if !ok {
		return nil, errors.New("exp not found")
	}
	expF, ok := exp.(float64)
	if !ok {
		return nil, errors.New("exp is not a int")
	}
	expInt := int64(expF)
	if expInt <= time.Now().Unix() {
		return nil, errors.New("exp is in the past")
	}
	iat, ok := claimsMap["iat"]
	if !ok {
		claimsMap["iat"] = time.Now().Unix()
	}
	iatF, ok := iat.(float64)
	if !ok {
		return nil, errors.New("iat is not a int")
	}
	iatInt := int64(iatF)
	if iatInt <= 0 {
		return nil, errors.New("iat is not a positive integer")
	}
	iss, ok := claimsMap["iss"]
	if !ok {
		return nil, errors.New("iss not found")
	}
	issStr, ok := iss.(string)
	if !ok {
		return nil, errors.New("iss is not a string")
	}
	if issStr == "" {
		return nil, errors.New("iss is an empty string")
	}
	return json.Marshal(claimsMap)
}

// GenerateJWT generates a JWT token with the provided claims, secret, and algorithm
// The claims should be a struct or map[string]any. The secret should be a string for HMAC algorithms,
// *rsa.PrivateKey for RSA algorithms, and *ecdsa.PrivateKey for ECDSA algorithms. The alg should be one of the
// supported algorithm constants. The function returns the JWT token as a string and an error if any.
// Note that the passed claims will be modified to include the "iat" field if it is not present. The "exp" and "iss"
// fields are required in the claims.
func GenerateJWT[T string | *rsa.PrivateKey | *ecdsa.PrivateKey](claims any, secret T, alg Algorithm) (string, error) {
	jsonPayload, err := marshalClaims(claims)
	if err != nil {
		return "", fmt.Errorf("error encoding payload: %w", err)
	}
	data := encodeHeader(alg) + "." + encodePayload(jsonPayload)
	signature, err := generateSignature(data, secret, alg)
	if err != nil {
		return "", fmt.Errorf("error generating signature: %w", err)
	}
	return data + "." + signature, nil
}
