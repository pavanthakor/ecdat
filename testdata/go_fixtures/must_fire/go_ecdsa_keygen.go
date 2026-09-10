package mustfire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func NewSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
