package mustfire

import (
	"crypto/ecdh"
	"crypto/rand"
)

// Key agreement over P-384: Shor-broken, replace with ML-KEM or a hybrid.
func Agree() ([]byte, error) {
	curve := ecdh.P384()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv.Bytes(), nil
}
