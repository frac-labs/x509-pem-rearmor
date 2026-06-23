// Package main is a reverse-proxy sidecar that rearmors Traefik's
// passTLSClientCert "pem: true" middleware output as URL-encoded PEM with
// a single-line base64 body, comma-joined when multiple certs — the shape
// Keycloak's `nginx` provider X509 SPI accepts when its armor-stripped body
// is fed to java.util.Base64.getDecoder() (BASIC, RFC 4648, whitespace-rejecting).
//
// See ADR-0012 (frac-labs/clawdiovascular) and references/traefik-keycloak-x509-spi-pem-decode.md.
//
// v0.1.1 (cdv#241): split input on `,` before armoring so leaf+chain are
// emitted as two separate URL-encoded PEM blocks joined by `,`.
//
// v0.1.2 (cdv#241): emit b64 body as a SINGLE line (no 64-col wrap),
// because KC's nginx SPI hands armor-stripped body to Java's basic Base64
// decoder which rejects embedded whitespace.
//
// v0.1.3 (cdv#241): DROP the `BEGIN`/`BEGIN%20CERTIFICATE` pass-through
// guards. Empirical (live KC keycloak-keycloakx-0 logs 2026-06-23T18:55Z):
// Traefik's passTLSClientCert{pem:true} emits URL-encoded armored PEM
// with 64-col-wrapped b64 body (separated by %0A). The v0.1.2 guard
// matched `BEGIN%20CERTIFICATE` in that input and returned it unchanged,
// so v0.1.2's single-line emit code never executed — 45 PemException
// traces in 20min after the sidecar rolled. v0.1.3 unconditionally
// normalizes any input shape (bare-base64-DER, literal armored PEM, or
// URL-encoded armored PEM) to single-line-body URL-encoded armored PEM.
// Idempotent on its own output.
// Anti-pattern: `references/transformation-skipped-by-format-guard.md`.
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

// stripWhitespace removes all ASCII whitespace from s.
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}

// rearmorOne unconditionally normalizes a single cert entry to a
// URL-encoded single-line-body PEM block. Accepts bare base64-DER,
// literal armored PEM (with or without 64-col wrap), URL-encoded
// armored PEM (Traefik's actual output shape with `%20` for space and
// `%0A` for newline, OR `+` for space — both valid URL-encodings), or
// already-correct v0.1.3 output (idempotent).
//
// Strategy: if the input contains `%` URL-escape markers we decode with
// url.QueryUnescape (handles both `+`→space and `%XX` percent-encoded
// bytes — this is what KC's java.net.URLDecoder does). If there's no
// `%` the input is a bare base64-DER blob (which never legitimately
// contains `+` AND `%` — base64 alphabet has no `%`). We then strip
// armor lines and whitespace from the body, and re-armor+encode.
func rearmorOne(raw string) string {
	if raw == "" {
		return raw
	}
	s := raw
	if strings.Contains(s, "%") {
		if decoded, err := url.QueryUnescape(s); err == nil {
			s = decoded
		}
	}
	// Strip armor lines (any number — defensive against doubled armor).
	s = strings.ReplaceAll(s, pemBegin, "")
	s = strings.ReplaceAll(s, pemEnd, "")
	// Strip all whitespace (incl. the \n that separated 64-col chunks).
	s = stripWhitespace(s)
	if s == "" {
		return raw
	}
	var buf bytes.Buffer
	buf.WriteString(pemBegin)
	buf.WriteString("\n")
	buf.WriteString(s)
	buf.WriteString("\n")
	buf.WriteString(pemEnd)
	buf.WriteString("\n")
	return url.QueryEscape(buf.String())
}

// rearmor splits a Traefik passTLSClientCert pem:true header value on `,`
// (one entry per cert in the chain — leaf first, then issuer(s)),
// rearmors each entry independently, and rejoins with `,`.
func rearmor(raw string) string {
	if raw == "" {
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
	log.Printf("x509-pem-rearmor v0.1.3 listening on %s, upstream %s", listen, upstreamURL)
	if err := http.ListenAndServe(listen, proxy); err != nil {
		log.Fatal(err)
	}
}
