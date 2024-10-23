package ezjwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gcottom/ezjwt"
	"github.com/stretchr/testify/assert"
)

func TestCreateJWT(t *testing.T) {
	t.Run("create and validate jwt", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		jwt, err := ezjwt.Decode(out)
		assert.NoError(t, err)
		assert.Len(t, jwt.Claims(), 3)
		assert.Equal(t, "test", jwt.Claims()["iss"])
		assert.Equal(t, claims["exp"], int64(jwt.Claims()["exp"].(float64)))
		assert.Equal(t, claims["iat"], int64(jwt.Claims()["iat"].(float64)))
		assert.False(t, jwt.IsExpired())
	})
	t.Run("error case - create jwt with nil claims", func(t *testing.T) {
		out, err := ezjwt.GenerateJWT(nil, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "claims cannot be nil")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - marshal error", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		claims["invalid"] = make(chan int)
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "error marshalling claims")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - exp not found", func(t *testing.T) {
		claims := make(map[string]any)
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "exp not found")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - exp is not a int", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = "invalid"
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "exp is not a int")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - exp is in the past", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "exp is in the past")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - iat is not a int", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = "invalid"
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "iat is not a int")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - iat is not a positive integer", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = -1
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "iat is not a positive integer")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - iss not found", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "iss not found")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - iss is not a string", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = 123
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "iss is not a string")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid claims - iss is an empty string", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = ""
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "iss is an empty string")
		assert.Empty(t, out)
	})
	t.Run("error case - create jwt with invalid algorithm", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", "invalid")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "unsupported algorithm: invalid")
		assert.Empty(t, out)
	})

	// these functions require private keys so a string secret creates an error
	invKeyAlgs := []ezjwt.Algorithm{ezjwt.RS256, ezjwt.RS384, ezjwt.RS512, ezjwt.ES256, ezjwt.ES384,
		ezjwt.ES512, ezjwt.PS256, ezjwt.PS384, ezjwt.PS512}
	for _, alg := range invKeyAlgs {
		t.Run("error case - create jwt with invalid private key - "+string(alg), func(t *testing.T) {
			claims := make(map[string]any)
			claims["exp"] = time.Now().Add(time.Hour).Unix()
			claims["iat"] = time.Now().Unix()
			claims["iss"] = "test"
			out, err := ezjwt.GenerateJWT(claims, "123456", alg)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "invalid private key type")
			assert.Empty(t, out)
		})
	}
	rsaKeyAlgs := []ezjwt.Algorithm{ezjwt.RS256, ezjwt.RS384, ezjwt.RS512, ezjwt.PS256, ezjwt.PS384, ezjwt.PS512}
	for _, alg := range rsaKeyAlgs {
		t.Run("error case - create jwt with private key signing error - "+string(alg), func(t *testing.T) {
			claims := make(map[string]any)
			claims["exp"] = time.Now().Add(time.Hour).Unix()
			claims["iat"] = time.Now().Unix()
			claims["iss"] = "test"

			// generate a private key that is invalid to provoke a signing error
			// with rsa we generate an invalid key by using a bad number of bits
			pk, err := rsa.GenerateKey(rand.Reader, 256)
			assert.NoError(t, err)
			fmt.Println(pk.N.BitLen())
			out, err := ezjwt.GenerateJWT(claims, pk, alg)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "error signing data")
			assert.Empty(t, out)
		})
	}
	ecdsaKeyAlgs := []ezjwt.Algorithm{ezjwt.ES256, ezjwt.ES384, ezjwt.ES512}
	for _, alg := range ecdsaKeyAlgs {
		t.Run("error case - create jwt with private key signing error - "+string(alg), func(t *testing.T) {
			claims := make(map[string]any)
			claims["exp"] = time.Now().Add(time.Hour).Unix()
			claims["iat"] = time.Now().Unix()
			claims["iss"] = "test"

			// generate a private key that is invalid to provoke a signing error
			// with ecdsa we generate an invalid key by using a bad curve
			curve := elliptic.P256()
			curve.Params().B = big.NewInt(0)
			order := curve.Params().N
			pk := new(ecdsa.PrivateKey)
			pk.PublicKey.Curve = curve
			pk.D = new(big.Int).Add(order, big.NewInt(10000000))

			out, err := ezjwt.GenerateJWT(claims, pk, alg)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "error signing data")
			assert.Empty(t, out)
		})
	}
}

func TestDecodeInvalidToken(t *testing.T) {
	t.Run("invalid token - not enough parts", func(t *testing.T) {
		out, err := ezjwt.Decode("invalid")
		assert.Error(t, err)
		assert.Empty(t, out)
	})
	t.Run("invalid token - invalid payload", func(t *testing.T) {
		out, err := ezjwt.Decode("invalid.inv^lid.invalid")
		assert.Error(t, err)
		assert.Empty(t, out)
	})
	t.Run("invalid token - error unamrshalling payload", func(t *testing.T) {
		out, err := ezjwt.Decode("invalid..invalid")
		assert.Error(t, err)
		assert.Empty(t, out)
	})
	t.Run("invalid token - exp not found", func(t *testing.T) {
		out, err := ezjwt.Decode("invalid.e30.invalid")
		assert.Error(t, err)
		assert.Empty(t, out)
	})
}

func TestUnmarshalClaimsError(t *testing.T) {
	t.Run("error case - unmarshal claims with invalid payload", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		jwt, err := ezjwt.Decode(out)
		assert.NoError(t, err)
		err = jwt.UnmarshalClaims(nil)
		assert.Error(t, err)
	})
}

func TestIsValid(t *testing.T) {
	t.Run("valid token", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		valid, err := ezjwt.IsValid(out, "123456")
		assert.NoError(t, err)
		assert.True(t, valid)
	})
	t.Run("error case - invalid token - decode error", func(t *testing.T) {
		valid, err := ezjwt.IsValid("invalid", "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "error decoding token")
		assert.False(t, valid)
	})
	t.Run("error case - invalid token - token expired", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(3 * time.Second).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		time.Sleep(4 * time.Second)
		valid, err := ezjwt.IsValid(out, "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "token expired")
		assert.False(t, valid)
	})
	t.Run("error case - invalid token - error decoding header", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		split := strings.Split(out, ".")
		invalid := "invalid^." + split[1] + "." + split[2]
		valid, err := ezjwt.IsValid(invalid, "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "error decoding header")
		assert.False(t, valid)
	})
	t.Run("error case - invalid token - error unmarshalling header", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		split := strings.Split(out, ".")
		header := base64.RawURLEncoding.EncodeToString([]byte("invalid"))
		invalid := header + "." + split[1] + "." + split[2]
		valid, err := ezjwt.IsValid(invalid, "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "error unmarshalling header")
		assert.False(t, valid)
	})
	t.Run("error case - invalid token - alg not found in header", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		split := strings.Split(out, ".")
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
		invalid := header + "." + split[1] + "." + split[2]
		valid, err := ezjwt.IsValid(invalid, "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "alg not found")
		assert.False(t, valid)
	})
	t.Run("error case - invalid token - error generating verification signature", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		split := strings.Split(out, ".")
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"invalid"}`))
		invalid := header + "." + split[1] + "." + split[2]
		valid, err := ezjwt.IsValid(invalid, "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "error generating verification signature")
		assert.False(t, valid)
	})
	t.Run("error case - error decoding signature", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		out = out + "^a"
		assert.NoError(t, err)
		valid, err := ezjwt.IsValid(out, "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "error decoding signature")
		assert.False(t, valid)
	})
	t.Run("error case - invalid signature", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		out = out + "aaa"
		assert.NoError(t, err)
		valid, err := ezjwt.IsValid(out, "123456")
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid signature")
		assert.False(t, valid)
	})
}

func TestUnmarshalClaims(t *testing.T) {
	t.Run("unmarshal claims", func(t *testing.T) {
		claims := make(map[string]any)
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["iat"] = time.Now().Unix()
		claims["iss"] = "test"
		out, err := ezjwt.GenerateJWT(claims, "123456", ezjwt.HS256)
		assert.NoError(t, err)
		jwt, err := ezjwt.Decode(out)
		assert.NoError(t, err)
		var v map[string]any
		err = jwt.UnmarshalClaims(&v)
		assert.NoError(t, err)
		assert.Len(t, v, 3)
		assert.Equal(t, "test", v["iss"])
		assert.Equal(t, claims["exp"], int64(v["exp"].(float64)))
		assert.Equal(t, claims["iat"], int64(v["iat"].(float64)))
	})
}
