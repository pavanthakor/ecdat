package mustfire

// An embedded certificate. The sentinel in the body must reach no Finding.
const partnerCert = `-----BEGIN CERTIFICATE-----
GONOTAREALCERTGONOTAREALCERTGONOTAREALCERTGONOTAREALCERT00000000
-----END CERTIFICATE-----`

func Cert() string { return partnerCert }
