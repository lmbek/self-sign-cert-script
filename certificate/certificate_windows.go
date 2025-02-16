// (windows) use for local development only
//go:build windows

package certificate

import (
	"crypto/ecdsa"
	"crypto/tls"
	_ "embed"
	"fmt"
)

// //go:embed localhost.crt
var embeddedCert []byte

// //go:embed localhost.key
var embeddedKey []byte

// LoadEmbeddedCertificate loads the embedded certificate and private key as a TLS certificate using ECDSA.
func LoadEmbeddedCertificate() (*tls.Certificate, error) {
	// Ensure the certificate and private key are embedded correctly (PEM-encoded)
	cert, err := tls.X509KeyPair(embeddedCert, embeddedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded TLS certificate and key: %w", err)
	}

	// Verify the certificate and key use ECDSA
	parsedCert, err := tls.X509KeyPair(embeddedCert, embeddedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse embedded certificate and key: %w", err)
	}

	// Check if the private key is ECDSA
	switch parsedCert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// The key is ECDSA
		fmt.Println("Using ECDSA private key")
	default:
		return nil, fmt.Errorf("embedded private key is not ECDSA")
	}

	return &cert, nil
}
