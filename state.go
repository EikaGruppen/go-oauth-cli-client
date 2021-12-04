package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

func generateState() (state string, err error) {
	b := make([]byte, 20)
	_, err = rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("Generating state failed: %w", err)
	}
	return strings.ReplaceAll(base64.URLEncoding.EncodeToString(b), "=", ""), nil
}

