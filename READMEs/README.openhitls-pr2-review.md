# PR #2 Review Report: OpenHiTLS Backend Comments

Source PR: <https://github.com/pi-ixel/libwebsockets/pull/2>

This document summarizes all visible review comments from PR #2 and proposes concrete remediation plans for each one. The code locations below were mapped against the current repository state to make the feedback actionable.

## Review Summary Table

| # | Reviewer | Review comment | Likely code area | Issue type | Recommended fix |
|---|---|---|---|---|---|
| 1 | `pi-ixel` | 这里的宏太复杂了 | `lib/tls/tls.c` around the `lws_klog_dump()` feature gate | Maintainability / preprocessor complexity | Replace the long `#if` expression with one or two semantic feature macros, such as a dedicated keylog support macro, so the backend and transport conditions are easier to follow. |
| 2 | `baoyi84930` | 这里为啥openhitls构建可以看到SSL 的类型声明？ | `lib/tls/tls.c` in `lws_openhitls_klog_dump()` | Backend layering / type leakage | Remove OpenSSL `SSL` exposure from the OpenHiTLS path by introducing a backend-neutral helper that operates on `struct lws *` and the keylog line, with each backend resolving the `wsi` first. |
| 3 | `baoyi84930` | 为啥这里要fatal | `lib/tls/tls.c` in `alpn_cb_openhitls()` | ALPN error semantics | Do not return a fatal alert for every ALPN selection failure. Distinguish between “no protocol match” and true internal failures, returning `NOACK` for the former and fatal only for real internal errors. |
| 4 | `baoyi84930` | 这个地方为啥入参不是vhost->tls.ssl_ctx？ | `lib/tls/tls.c` in the OpenHiTLS ALPN callback registration | API consistency / encapsulation | Avoid reaching into `ctx->config` at the call site without a helper. Add an accessor that accepts `vhost->tls.ssl_ctx` and returns the backend config, or refactor the abstraction so callers do not know the wrapper layout. |
| 5 | `baoyi84930` | 确认一下，这个宏定义是不是冗余的 | `lib/tls/tls.c` near the ALPN unsupported logging branch | Redundant conditional compilation | Simplify the `#if/#elif/#else` structure so OpenHiTLS, mbedTLS, OpenSSL, and fallback cases are mutually exclusive, which should make the extra `!defined(LWS_WITH_OPENHITLS)` guard unnecessary. |
| 6 | `baoyi84930` | 为啥这里需要一个类型转换 | OpenHiTLS TLS-handle usage sites | Unnecessary casting | Replace direct casts with a backend-local getter/helper, or unify the local handle type so OpenHiTLS call sites can use `lws_tls_conn *` consistently without repeated explicit conversions. |
| 7 | `baoyi84930` | verify_result不是这几个错误码 | `lib/tls/openhitls/openhitls-client.c` in `lws_tls_client_confirm_peer_cert()` | Incorrect error-domain mixing | Remove the comparisons between `verify_result` and `HITLS_WANT_*`. `verify_result` should only carry certificate validation results; handshake progress states must be handled from the actual handshake return path. |
| 8 | `baoyi84930` | hostname 配flag验证吧 | `lib/tls/openhitls/openhitls-client.c` in `HITLS_X509_VerifyHostname(..., 0, ...)` | Incomplete API usage | Replace the literal `0` with the correct OpenHiTLS hostname verification flag(s), chosen to match existing OpenSSL/libwebsockets behavior as closely as possible. |
| 9 | `baoyi84930` | 验证成功的逻辑对吗 | `lib/tls/openhitls/private.h` in `lws_openhitls_verify_result_to_policy()` and related callers | Policy mapping correctness | Revisit the mapping from verification results to `ALLOW_*` policies so invalid CA, missing issuer/root, hostname mismatch, and time errors each map to the intended libwebsockets behavior without overlapping ad hoc overrides. |
| 10 | `baoyi84930` | 这个没必要，OP 对应关系也不太对 | `lib/tls/openhitls/private.h` in `lws_openhitls_apply_ssl_options()` | Overbroad compatibility mapping | Shrink the supported OpenSSL-option compatibility surface to the subset with clear OpenHiTLS equivalents and real libwebsockets callers. Warn and ignore unsupported options instead of defining and mapping many uncertain `SSL_OP_*` values. |

## Detailed Remediation Notes

### 1. Macro complexity in `lws_klog_dump()`
- Introduce a dedicated compile-time macro for keylog support, for example `LWS_WITH_TLS_KEYLOG_SUPPORT`.
- Keep backend-specific extraction of `wsi` outside the shared keylog file-writing logic.
- This reduces nested feature conditions and makes the compilation intent obvious.

### 2. OpenHiTLS path leaking `SSL` type names
- Refactor the implementation into a shared backend-neutral helper, for example:
  - `static void lws_klog_dump_wsi(struct lws *wsi, const char *line)`
- In the OpenSSL callback, derive `wsi` from `SSL *`.
- In the OpenHiTLS callback, derive `wsi` from `HITLS_Ctx *`.
- Call the shared helper from both paths.

### 3. ALPN callback returning fatal too aggressively
- Review the return-code contract of `HITLS_SelectAlpnProtocol()`.
- If the failure only means no common ALPN protocol was found, return `HITLS_ALPN_ERR_NOACK`.
- Reserve `HITLS_ALPN_ERR_ALERT_FATAL` for invalid state, bad inputs, or internal OpenHiTLS failures.
- Add logging so mismatches and internal failures are distinguishable.

### 4. ALPN registration should not expose `ctx->config`
- Add a tiny wrapper such as:
  - `HITLS_Config *lws_openhitls_ctx_config(void *ssl_ctx)`
- Make the ALPN registration code take `vhost->tls.ssl_ctx` and let the helper unwrap it.
- This keeps backend-private struct layout from leaking into generic TLS code.

### 5. Redundant macro guard near ALPN unsupported path
- Rewrite the surrounding conditional compilation as a single, mutually exclusive chain.
- This removes the need for nested or duplicated `LWS_WITH_OPENHITLS` exclusions.
- The result will also be easier to reason about during future backend additions.

### 6. Repeated explicit TLS-handle casts
- Add backend-local inline accessors for OpenHiTLS handle retrieval.
- Use those helpers instead of scattered casts, especially for `wsi->tls.ssl`.
- This improves readability and gives one place to change if the abstraction evolves.

### 7. `verify_result` compared against `HITLS_WANT_*`
- Delete the branch that treats `verify_result` as if it were a handshake status code.
- Handle `WANT_READ`, `WANT_WRITE`, `WANT_CONNECT`, and `WANT_ACCEPT` where the OpenHiTLS handshake API returns them.
- Keep `HITLS_GetVerifyResult()` strictly for certificate verification outcomes.
- This is the clearest correctness bug among the current review comments.

### 8. Hostname verification should use explicit flags
- Replace the literal `0` in `HITLS_X509_VerifyHostname()` with the proper OpenHiTLS flag value(s).
- Select the flag combination that best matches the existing OpenSSL client verification semantics already expected by libwebsockets.
- Add a code comment documenting the chosen behavior.

### 9. Recheck verify-result to policy mapping
- Consolidate the verification-result-to-policy decision so callers do not override it in multiple places.
- Model each verification result as:
  - a user-visible category string,
  - an allow-mask,
  - optional follow-up refinement such as self-signed detection.
- This makes the success / allowed-failure behavior easier to audit.

### 10. Narrow the `SSL_OP_*` compatibility layer
- Keep only options with a proven semantic equivalent in OpenHiTLS and a real use in libwebsockets.
- For unsupported or unclear mappings, log a warning and ignore them.
- Avoid defining a large set of OpenSSL-style fallback constants if they do not correspond cleanly to OpenHiTLS controls.
- This reduces the risk of “appears compatible, behaves differently” bugs.

## Suggested Priority

### P0: fix immediately
1. `verify_result` vs `HITLS_WANT_*` misuse.
2. Hostname verification flags.
3. ALPN fatal/noack differentiation.

### P1: fix in the same review round
4. Remove `SSL` type leakage from the OpenHiTLS path.
5. Clean up the `ssl_ctx -> ctx->config` access pattern.
6. Simplify redundant preprocessor guards.

### P2: cleanup / follow-up
7. Consolidate verify-policy mapping.
8. Shrink the `SSL_OP_*` compatibility matrix.
9. Centralize OpenHiTLS handle accessors.
10. Simplify the macro gate structure for keylog support.
