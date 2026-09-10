package mustfire

// must_fire: go-hardcoded-key-der (ADR-0034) -- a base64 DER structure is key
// material by its SHAPE alone. `MII` is a DER SEQUENCE with a two-byte length
// (X.690 s8.1.3), the header of every RSA key and every X.509 certificate
// (RFC 8017, RFC 5280). The body is filler; the sentinel must reach no Finding.

import "crypto/aes"

const partnerKeyDer = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAGODERSENTINELnotARealKeyJustFillerForTheShapeOnly0123456789"

// It reaches a key parameter too. The DER rule owns a shaped literal, so this
// is still ONE finding -- not a DER finding plus a sink finding.
func PartnerCipher() error {
	_, err := aes.NewCipher([]byte(partnerKeyDer))
	return err
}
