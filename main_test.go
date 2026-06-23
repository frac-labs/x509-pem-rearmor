package main

import (
	"net/url"
	"strings"
	"testing"
)

// mustDecodeToBody URL-decodes (QueryUnescape — same as KC's URLDecoder)
// and asserts the result is exactly three lines: BEGIN, single-line body,
// END. Returns the body.
func mustDecodeToBody(t *testing.T, encoded string) string {
	t.Helper()
	dec, err := url.QueryUnescape(encoded)
	if err != nil {
		t.Fatalf("not URL-decodable: %v (input: %q)", err, encoded)
	}
	lines := strings.Split(strings.TrimSpace(dec), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (BEGIN, body, END), got %d: %q", len(lines), lines)
	}
	if lines[0] != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("line 0 not BEGIN: %q", lines[0])
	}
	if lines[2] != "-----END CERTIFICATE-----" {
		t.Errorf("line 2 not END: %q", lines[2])
	}
	if strings.ContainsAny(lines[1], " \t\n\r") {
		t.Errorf("body line contains whitespace: %q", lines[1])
	}
	return lines[1]
}

func TestRearmorBareBase64(t *testing.T) {
	in := strings.Repeat("A", 100)
	body := mustDecodeToBody(t, rearmor(in))
	if body != in {
		t.Errorf("body mismatch: got %q want %q", body, in)
	}
}

func TestRearmorEmpty(t *testing.T) {
	if got := rearmor(""); got != "" {
		t.Errorf("empty input should return empty, got %q", got)
	}
}

// v0.1.3: input that is URL-encoded armored PEM with 64-col-wrapped body
// (Traefik passTLSClientCert pem:true actual output shape) must be
// normalized to single-line body. v0.1.0–v0.1.2 returned this UNCHANGED
// because of the pass-through guard, which is the cdv#241 root bug.
//
// Use percent-encoding (`%20` for space, `%0A` for newline) to model
// Traefik's actual output rather than Go's url.QueryEscape (which uses
// `+` for space) — the percent form is the one that lit the original
// `BEGIN%20CERTIFICATE` guard.
func TestRearmorNormalizesPercentEncodedWrappedPEM(t *testing.T) {
	body := strings.Repeat("A", 200) // > 64 chars to force wrap
	var wrapped strings.Builder
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		wrapped.WriteString(body[i:end])
		wrapped.WriteString("%0A")
	}
	in := "-----BEGIN%20CERTIFICATE-----%0A" + wrapped.String() + "-----END%20CERTIFICATE-----%0A"
	gotBody := mustDecodeToBody(t, rearmor(in))
	if gotBody != body {
		t.Errorf("body mismatch after normalize: got %q want %q", gotBody, body)
	}
}

// Same but with `+` for space (Go's QueryEscape style — also valid
// per application/x-www-form-urlencoded which URLDecoder.decode handles).
func TestRearmorNormalizesPlusEncodedWrappedPEM(t *testing.T) {
	body := strings.Repeat("A", 200)
	var wrapped strings.Builder
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		wrapped.WriteString(body[i:end])
		wrapped.WriteString("%0A")
	}
	in := "-----BEGIN+CERTIFICATE-----%0A" + wrapped.String() + "-----END+CERTIFICATE-----%0A"
	gotBody := mustDecodeToBody(t, rearmor(in))
	if gotBody != body {
		t.Errorf("body mismatch: got %q want %q", gotBody, body)
	}
}

// v0.1.3: literal armored PEM (no URL-encoding) with internal \n wrap
// must also be normalized to single-line body.
func TestRearmorNormalizesLiteralArmoredPEM(t *testing.T) {
	body := strings.Repeat("B", 150)
	literal := "-----BEGIN CERTIFICATE-----\n" + body[:64] + "\n" + body[64:128] + "\n" + body[128:] + "\n-----END CERTIFICATE-----\n"
	gotBody := mustDecodeToBody(t, rearmor(literal))
	if gotBody != body {
		t.Errorf("body mismatch: got %q want %q", gotBody, body)
	}
}

// v0.1.3: idempotency — running rearmor twice on the same input yields
// the same result as running it once.
func TestRearmorIdempotent(t *testing.T) {
	in := strings.Repeat("C", 100)
	once := rearmor(in)
	twice := rearmor(once)
	if once != twice {
		t.Errorf("not idempotent:\n once=%q\n twice=%q", once, twice)
	}
}

// v0.1.1: Traefik emits leaf+chain as bare-base64 blobs joined by `,`.
// Each must be armored independently and rejoined with `,`.
func TestRearmorMultiCertSplitsOnComma(t *testing.T) {
	leaf := strings.Repeat("A", 100)
	chain := strings.Repeat("B", 80)
	in := leaf + "," + chain
	got := rearmor(in)
	parts := strings.Split(got, ",")
	if len(parts) != 2 {
		t.Fatalf("expected 2 comma-separated entries, got %d", len(parts))
	}
	body0 := mustDecodeToBody(t, parts[0])
	if body0 != leaf {
		t.Errorf("leaf body mismatch: got %q want %q", body0, leaf)
	}
	body1 := mustDecodeToBody(t, parts[1])
	if body1 != chain {
		t.Errorf("chain body mismatch: got %q want %q", body1, chain)
	}
}

// Multi-cert URL-encoded armored input (Traefik real shape with chain).
func TestRearmorMultiCertPercentEncoded(t *testing.T) {
	leaf := strings.Repeat("X", 100)
	chain := strings.Repeat("Y", 80)
	mk := func(b string) string {
		var w strings.Builder
		for i := 0; i < len(b); i += 64 {
			end := i + 64
			if end > len(b) {
				end = len(b)
			}
			w.WriteString(b[i:end])
			w.WriteString("%0A")
		}
		return "-----BEGIN%20CERTIFICATE-----%0A" + w.String() + "-----END%20CERTIFICATE-----%0A"
	}
	in := mk(leaf) + "," + mk(chain)
	parts := strings.Split(rearmor(in), ",")
	if len(parts) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parts))
	}
	if got := mustDecodeToBody(t, parts[0]); got != leaf {
		t.Errorf("leaf: got %q want %q", got, leaf)
	}
	if got := mustDecodeToBody(t, parts[1]); got != chain {
		t.Errorf("chain: got %q want %q", got, chain)
	}
}
