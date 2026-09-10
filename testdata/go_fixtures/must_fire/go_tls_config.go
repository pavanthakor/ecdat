package mustfire

import "crypto/tls"

func LegacyConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS10,
		CipherSuites:     []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
}
