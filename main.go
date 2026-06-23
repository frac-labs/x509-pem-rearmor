// Package main is a reverse-proxy sidecar that rearmors Traefik's
// passTLSClientCert "pem: true" middleware output (bare base64-DER, no armor,
// comma-separated when multiple certs) as URL-encoded PEM with %0A line
// breaks, comma-joined — the shape Keycloak's haproxy-provider X509 SPI
// expects for X-Forwarded-Tls-Client-Cert.
//
// See ADR-0012 (frac-labs/clawdiovascular) and references/traefik-keycloak-x509-spi-pem-decode.md.
//
// v0.1.1 (cdv#241): split input on `,` before armoring so leaf+chain are
// emitted as two separate URL-encoded PEM blocks joined by `,`, instead of
// wrapped together as one block (which produced invalid base64 in the body).
// Also widened the pass-through guard to match either literal `BEGIN` or
// URL-encoded `BEGIN%20` so already-armored input is never re-encoded.
//
// v0.1.2 (cdv#241): emit b64 body as a SINGLE line (no 64-col wrap).
// Empirical wire-capture (echo-debug Pod 2026-06-23T17:20Z) showed that
// Keycloak's nginx-provider SPI URL-decodes correctly but then hands the
// armor-stripped body to java.util.Base64.getDecoder() (BASIC decoder,
// RFC 4648, whitespace-rejecting — NOT getMimeDecoder()). The v0.1.1
// 64-col wrap embedded `\n` separators that survived URL-decode and
// triggered PemException at byte 574. PEM-armor compatibility is NOT
// Base64-decoder compatibility: armor + URL-encoding can both be
// "correct" while the wrap convention inside still breaks decode.
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

// rearmorOne wraps a single bare base64-DER blob as URL-encoded PEM
// (BEGIN/END armor, 64-col wrapped, then url.QueryEscape the whole thing).
// If the input already contains a BEGIN marker (literal or %20-encoded),
// it's returned unchanged.
func rearmorOne(raw string) string {
	if raw == "" {
		return raw
	}
	if strings.Contains(raw, "BEGIN CERTIFICATE") || strings.Contains(raw, "BEGIN%20CERTIFICATE") {
		return raw
	}
	stripped := strings.ReplaceAll(strings.ReplaceAll(raw, "\n", ""), "\r", "")
	stripped = strings.TrimSpace(stripped)
	if stripped == "" {
		return raw
	}
	var buf bytes.Buffer
	buf.WriteString(pemBegin)
	buf.WriteString("\n")
	buf.WriteString(stripped)
	buf.WriteString("\n")
	buf.WriteString(pemEnd)
	buf.WriteString("\n")
	return url.QueryEscape(buf.String())
}

// rearmor splits a Traefik passTLSClientCert pem:true header value on `,`
// (one entry per cert in the chain — leaf first, then issuer(s)), rearmors
// each entry independently, and rejoins with `,`. This matches the haproxy
// SPI shape Keycloak expects: comma-separated URL-encoded PEM blocks.
func rearmor(raw string) string {
	if raw == "" {
		return raw
	}
	// If the whole value already contains armor (literal or URL-encoded),
	// pass through — don't double-encode.
	if strings.Contains(raw, "BEGIN CERTIFICATE") || strings.Contains(raw, "BEGIN%20CERTIFICATE") {
		return raw
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, rearmorOne(p))
	}
	return strings.Join(out, ",")
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
	log.Printf("x509-pem-rearmor v0.1.2 listening on %s, upstream %s", listen, upstreamURL)
	if err := http.ListenAndServe(listen, proxy); err != nil {
		log.Fatal(err)
	}
}
