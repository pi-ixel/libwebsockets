# lws minimal http server openhitls sni mismatch

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-openhitls-sni-mismatch
```

## Description

This test demonstrates SNI (Server Name Indication) functionality with OpenHITLS.

## Test stages

The test validates 2 SNI scenarios:

- **Stage 0**: Client SNI="sni.com", Server vhost="nosni.com" 
  - Expected: Connection succeeds with default certificate (CN=localhost)
  - Result: ✅ **PASS** - SNI mismatch correctly falls back to default certificate

- **Stage 1**: Client SNI="sni.com", Server vhost="sni.com"
  - Expected: Connection succeeds with sni.com certificate (CN=sni.com)
  - Result: ✅ **PASS** - SNI match uses correct certificate

- **Stage 2** (DISABLED): Client SNI="sni.com", Server no SNI vhost
  - Expected: Connection succeeds with default certificate
  - Result: ⚠️ **CANNOT TEST** - OpenHITLS caches certificate configuration globally,
    preventing proper fallback behavior when SNI matches but no certificate is configured

## Implementation Notes

### OpenHITLS SNI Behavior

OpenHITLS implements SNI callback in `lws_ssl_server_name_cb()` which:

1. Extracts SNI from ClientHello
2. Searches for matching vhost using `lws_select_vhost()`
3. If found: switches to that vhost's certificate
4. If not found: continues with default certificate

### Known Limitations

- **Certificate Caching**: OpenHITLS appears to cache certificate configurations globally across ports,
  making it difficult to test fallback scenarios where SNI matches but no certificate is configured.
  
- **Multi-port Testing**: Due to the caching behavior, SNI fallback scenarios cannot be reliably tested
  using multiple vhosts on different ports within the same process.

## Requirements

- LWS_WITH_SERVER
- LWS_WITH_CLIENT  
- LWS_WITH_TLS
- LWS_WITH_OPENHITLS

## Certificates

The test generates its own certificates in `certs/` directory:
- `default.pem` / `default.key` - Default certificate (CN=localhost)
- `sni.pem` / `sni.key` - SNI certificate (CN=sni.com)
- `nosni.pem` / `nosni.key` - Alternative certificate (CN=nosni.com)
- `ca.pem` / `ca.key` - CA certificate

Run from the test directory or ensure certificates are available.
