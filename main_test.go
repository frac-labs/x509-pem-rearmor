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

func TestRearmorWraps64Cols(t *testing.T) {
	in := strings.Repeat("A", 200)
	got, err := url.QueryUnescape(rearmor(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if line == "-----BEGIN CERTIFICATE-----" || line == "-----END CERTIFICATE-----" {
			continue
		}
		if len(line) > 64 {
			t.Errorf("line longer than 64 cols: %d", len(line))
		}
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
