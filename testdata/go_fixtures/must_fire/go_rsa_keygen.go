package mustfire

import (
	"crypto/rand"
	"crypto/rsa"
)

// RSA key generation. Quantum-broken outright; key size does not help.
func NewTransportKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
