package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestRearmorWrapsBareBase64(t *testing.T) {
	in := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJxxxxxxxxxxxxxx"
	got := rearmor(in)
	dec, err := url.QueryUnescape(got)
	if err != nil {
		t.Fatalf("not URL-decodable: %v", err)
	}
	if !strings.Contains(dec, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("missing BEGIN: %q", dec)
	}
	if !strings.Contains(dec, "-----END CERTIFICATE-----") {
		t.Errorf("missing END: %q", dec)
	}
	if !strings.Contains(dec, "\n") {
		t.Errorf("missing newlines after URL-decode")
	}
}

func TestRearmorPassesThroughIfAlreadyArmored(t *testing.T) {
	in := "-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----"
	if got := rearmor(in); got != in {
		t.Errorf("expected pass-through, got %q", got)
	}
}

func TestRearmorPassesThroughIfURLEncodedArmored(t *testing.T) {
	in := "-----BEGIN%20CERTIFICATE-----%0AABCD%0A-----END%20CERTIFICATE-----"
	if got := rearmor(in); got != in {
		t.Errorf("expected pass-through for URL-encoded armor, got %q", got)
	}
}

func TestRearmorEmpty(t *testing.T) {
	if got := rearmor(""); got != "" {
		t.Errorf("empty input should return empty, got %q", got)
	}
}

// TestRearmorEmitsSingleLineBody verifies the v0.1.2 fix: the b64 body
// between BEGIN/END armor must be a single line (no `\n` separators).
// Empirical: Keycloak's SPI uses java.util.Base64.getDecoder() (BASIC,
// whitespace-rejecting) on the armor-stripped body — 64-col-wrap with
// embedded newlines triggered PemException at byte 574 (cdv#241).
func TestRearmorEmitsSingleLineBody(t *testing.T) {
	in := strings.Repeat("A", 200)
	got, err := url.QueryUnescape(rearmor(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Trim trailing newline so split doesn't yield an empty final element.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected exactly 3 lines (BEGIN, body, END), got %d: %q", len(lines), lines)
	}
	if lines[0] != "-----BEGIN CERTIFICATE-----" {
		t.Errorf("line 0 not BEGIN: %q", lines[0])
	}
	if lines[2] != "-----END CERTIFICATE-----" {
		t.Errorf("line 2 not END: %q", lines[2])
	}
	if lines[1] != in {
		t.Errorf("body line should be input verbatim (single line, no wrap), got %q", lines[1])
	}
}

// TestRearmorMultiCertSplitsOnComma exercises the v0.1.1 fix: Traefik
// passTLSClientCert pem:true emits leaf+chain as two bare base64-DER blobs
// joined by `,`. Each must be armored independently and rejoined with `,`,
// NOT wrapped together as one PEM block (which would embed `,` in the
// base64 body and yield invalid base64 to Keycloak's HaProxy SPI provider).
func TestRearmorMultiCertSplitsOnComma(t *testing.T) {
	leaf := strings.Repeat("A", 100)
	chain := strings.Repeat("B", 80)
	in := leaf + "," + chain
	got := rearmor(in)
	parts := strings.Split(got, ",")
	if len(parts) != 2 {
		t.Fatalf("expected 2 comma-separated entries, got %d: %q", len(parts), got)
	}
	for i, p := range parts {
		dec, err := url.QueryUnescape(p)
		if err != nil {
			t.Fatalf("part %d not URL-decodable: %v", i, err)
		}
		if !strings.Contains(dec, "-----BEGIN CERTIFICATE-----") || !strings.Contains(dec, "-----END CERTIFICATE-----") {
			t.Errorf("part %d missing armor: %q", i, dec)
		}
		// No `,` should appear inside the URL-decoded body — it must be
		// pure base64 between BEGIN/END.
		body := dec
		body = strings.TrimPrefix(body, "-----BEGIN CERTIFICATE-----\n")
		body = strings.TrimSuffix(body, "\n")
		body = strings.TrimSuffix(body, "-----END CERTIFICATE-----")
		if strings.Contains(body, ",") {
			t.Errorf("part %d body contains comma (chain leak): %q", i, body)
		}
	}
	// Leaf must be in part 0, chain in part 1 (order preserved).
	// The 64-col wrapper inserts \n into the body, so strip newlines
	// before comparing against the contiguous input.
	dec0, _ := url.QueryUnescape(parts[0])
	flat0 := strings.ReplaceAll(dec0, "\n", "")
	if !strings.Contains(flat0, leaf) {
		t.Errorf("part 0 does not contain leaf body")
	}
	dec1, _ := url.QueryUnescape(parts[1])
	flat1 := strings.ReplaceAll(dec1, "\n", "")
	if !strings.Contains(flat1, chain) {
		t.Errorf("part 1 does not contain chain body")
	}
}
