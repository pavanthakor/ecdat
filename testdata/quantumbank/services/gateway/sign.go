// QuantumBank API gateway: request signing for partner callbacks.
// NOTE: Go is out of scope for ECDAT's source scanner today (Python only,
// ADR-0004), so everything here is a KNOWN GAP in the answer key.
package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

const partnerCert = `-----BEGIN CERTIFICATE-----
NOTAREALCERTNOTAREALCERTNOTAREALCERTNOTAREALCERTNOTAREALCERT0000
-----END CERTIFICATE-----`

func NewSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
