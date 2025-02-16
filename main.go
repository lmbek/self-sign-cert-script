package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"self-sign-cert/certificate"
	"self-sign-cert/internal"
)

func main() {
	// TEST SERVER CAN BE USED, BUT BE AWARE THAT EMBEDDING USES PREVIOUS LOCALHOST CERT,
	// SO THE CREATE SELFSIGNED AND TESTSERVER CANT RUN AT THE SAME TIME!

	// FIRST FLIP THE IF STATEMENT
	// SECOND UNCOMMENT THE EMBEDS INSIDE certificate_windows.go
	// if you don't uncomment the embeds this err will come:
	// selfsigning failed: failed to load embedded TLS certificate and key: tls: failed to find any PEM data in certificate input

	if true {
		certName := "localhost"
		orgNames := []string{"Local MyCompany Cert"}
		dnsNames := []string{"localhost"}

		internal.CreateSelfSignedCertificateFile(certName, orgNames, dnsNames)
		return
	}

	// Test HTTPS server setup
	testServer()
}

func testServer() {
	httpsServer := &http.Server{}

	// Load self-signed or managed certificate (using embedded certs here)
	selfSigned, err := certificate.LoadEmbeddedCertificate()
	if err != nil {
		log.Fatalf("selfsigning failed: %v", err)
	}

	httpsServer.Addr = "localhost:443"
	httpsServer.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13, // Enforce TLS 1.3
		MaxVersion:   tls.VersionTLS13, // Allow only TLS 1.3
		NextProtos:   []string{"h2"},   // Enforce HTTP/2
		Certificates: []tls.Certificate{*selfSigned},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519, // Strong elliptic curve for forward secrecy
		},
		InsecureSkipVerify:     false, // Ensure no certificate verification is skipped
		SessionTicketsDisabled: false,
	}

	// Initialize the mux for HTTP handlers
	mux := http.NewServeMux()

	// Define your handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Log connection details
		w.Write([]byte("Secure server is up and running"))
	})

	httpsServer.Handler = mux

	fmt.Println("Listening on: https://" + httpsServer.Addr)

	// Start the server
	err = httpsServer.ListenAndServeTLS("", "") // Certs are already loaded into the server config
	if err != nil {
		log.Fatalf("Failed to start the server: %v", err)
	}
}
