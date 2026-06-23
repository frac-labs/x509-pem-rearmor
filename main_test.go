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
