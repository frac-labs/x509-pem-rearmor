// Package main is a reverse-proxy sidecar that rearmors Traefik's
// passTLSClientCert "pem: true" middleware output (bare base64-DER, no armor)
// as URL-encoded PEM with %0A line breaks, which is the shape Keycloak's
// haproxy-provider X509 SPI expects for X-Forwarded-Tls-Client-Cert.
//
// See ADR-0012 (frac-labs/clawdiovascular) and references/traefik-keycloak-x509-spi-pem-decode.md.
package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

const (
	headerName = "X-Forwarded-Tls-Client-Cert"
	pemBegin   = "-----BEGIN CERTIFICATE-----"
	pemEnd     = "-----END CERTIFICATE-----"
)

// rearmor wraps a single base64-DER body with PEM armor + URL-encoded
// newlines (%0A), the shape Keycloak's haproxy X509 SPI accepts.
// If the value already contains a BEGIN marker, returns it unchanged.
func rearmor(raw string) string {
	if raw == "" || strings.Contains(raw, "BEGIN CERTIFICATE") {
		return raw
	}
	// Traefik may already chunk by 64 cols or emit a single line; either way,
	// wrap as: BEGIN\n<base64 unchanged>\nEND with %0A separators URL-encoded.
	var buf bytes.Buffer
	buf.WriteString(pemBegin)
	buf.WriteString("\n")
	// Re-wrap to 64 columns to be safe (haproxy provider tolerates wrap).
	stripped := strings.ReplaceAll(strings.ReplaceAll(raw, "\n", ""), "\r", "")
	for i := 0; i < len(stripped); i += 64 {
		end := i + 64
		if end > len(stripped) {
			end = len(stripped)
		}
		buf.WriteString(stripped[i:end])
		buf.WriteString("\n")
	}
	buf.WriteString(pemEnd)
	buf.WriteString("\n")
	return url.QueryEscape(buf.String())
}

func main() {
	upstreamURL := os.Getenv("UPSTREAM_URL")
	if upstreamURL == "" {
		log.Fatal("UPSTREAM_URL env var required (e.g. http://localhost:8080)")
	}
	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = ":8080"
	}
	u, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("UPSTREAM_URL parse: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		if v := r.Header.Get(headerName); v != "" {
			r.Header.Set(headerName, rearmor(v))
		}
	}
	log.Printf("x509-pem-rearmor listening on %s, upstream %s", listen, upstreamURL)
	if err := http.ListenAndServe(listen, proxy); err != nil {
		log.Fatal(err)
	}
}
