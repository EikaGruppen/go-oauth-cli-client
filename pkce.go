package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"strings"
	"time"
)

const (
	DefaultLength = 32
)

type codeVerifier struct {
	value string
}

func createCodeVerifier() (*codeVerifier, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, DefaultLength, DefaultLength)
	for i := 0; i < DefaultLength; i++ {
		b[i] = byte(r.Intn(255))
	}
	return &codeVerifier{
		value: encode(b),
	}, nil
}

func (v *codeVerifier) String() string {
	return v.value
}

func (v *codeVerifier) codeChallengeS256() string {
	h := sha256.New()
	h.Write([]byte(v.value))
	return encode(h.Sum(nil))
}

func encode(msg []byte) string {
	encoded := base64.StdEncoding.EncodeToString(msg)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)
	return encoded
}
