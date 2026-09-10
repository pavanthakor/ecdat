package mustfire

// An embedded private key. Never a Finding's snippet.
const signingKey = `-----BEGIN RSA PRIVATE KEY-----
GONOTAREALKEYGONOTAREALKEYGONOTAREALKEYGONOTAREALKEY000000000000
-----END RSA PRIVATE KEY-----`

func Key() string { return signingKey }
