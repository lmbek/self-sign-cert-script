// (windows) use for local development only
//go:build !windows

package certificate

import (
	"crypto/tls"
	_ "embed"
	"log"
)

// LoadEmbeddedCertificate loads the embedded certificate and private key as a TLS certificate using ECDSA.
func LoadEmbeddedCertificate() (*tls.Certificate, error) {
	log.Fatal("This self-signed certificate for localhost dev is not implemented for linux yet in this project")
	return nil, nil
}
