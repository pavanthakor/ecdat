package mustfire

import (
	"crypto/ecdsa"
	"math/big"
)

// The VERIFY side of ECDSA -- the side that must accept ML-DSA (FIPS 204)
// before any signer can emit it. Both entry points: the (r, s) form and the
// ASN.1-encoded form.

func CheckSignature(pub *ecdsa.PublicKey, digest []byte, r, s *big.Int) bool {
	return ecdsa.Verify(pub, digest, r, s)
}

func CheckSignatureASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, digest, sig)
}
