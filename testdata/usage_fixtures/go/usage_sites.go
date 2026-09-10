// Go call sites whose API names the usage (ADR-0030).
package usagesites

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// EncryptOAEP is KEY TRANSPORT: RSA wrapping a symmetric key.
func WrapSessionKey(pub *rsa.PublicKey, sessionKey []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sessionKey, nil)
}

// VerifyPKCS1v15 VERIFIES.
func CheckSignature(pub *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, 0, digest, sig)
}
