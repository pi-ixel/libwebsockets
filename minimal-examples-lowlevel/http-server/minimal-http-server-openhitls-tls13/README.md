# lws minimal http server openhitls tls13

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-openhitls-tls13 --port 7782
```

## Description

This test demonstrates TLS 1.3 connection establishment and application data transfer using OpenHITLS.

## Test scenario

- Client and server negotiate TLS 1.3 connection
- Establish secure TLS 1.3 channel
- Send 1024 bytes of application data
- Server echoes the data back to client
- Expect connection success and data transfer success

## Requirements

- LWS_WITH_SERVER
- LWS_WITH_CLIENT  
- LWS_WITH_TLS
- LWS_WITH_OPENHITLS

## Certificates

The test uses the default test certificates from the parent directory:
- libwebsockets-test-server.pem
- libwebsockets-test-server.key.pem

Run from the parent http-server directory or copy certificates to current directory.

## TLS 1.3 Features

This test verifies:
- TLS 1.3 protocol negotiation
- Application data encryption/decryption
- Large payload handling (1024 bytes)
- Full duplex communication (send and receive)
