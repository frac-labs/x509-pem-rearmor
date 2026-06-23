# x509-pem-rearmor

Sidecar reverse-proxy: rearmors Traefik's `passTLSClientCert: pem: true` bare-base64-DER `X-Forwarded-Tls-Client-Cert` header as URL-encoded PEM with `%0A` separators (haproxy-shape). Forwards to upstream Keycloak (or any consumer expecting `KC_SPI_X509CERT_LOOKUP_PROVIDER=haproxy` header format).

See `frac-labs/clawdiovascular` ADR-0012 (issue/PR-229) and `references/traefik-keycloak-x509-spi-pem-decode.md`.

## Run

```
docker run --rm -p 8080:8080 \
  -e UPSTREAM_URL=http://keycloak:8080 \
  docker.io/ctrahey/x509-pem-rearmor:0.1.0
```

Environment:
- `UPSTREAM_URL` (required) — destination URL.
- `LISTEN_ADDR` (default `:8080`).

## License

MIT.
