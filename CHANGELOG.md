## 2.0.0

### Breaking

- Constructor now uses named parameters: `DigestAuth(username: ..., password: ...)`.
- Fields (`realm`, `nonce`, `opaque`, `uri`) are now read-only getters.
- `getAuthString()` deprecated in favor of `buildAuthorizationHeader()`.

### Added

- SHA-256 and SHA-512/256 algorithm support via `DigestAlgorithm` enum.
- Automatic algorithm negotiation from server challenges; explicit algorithm validated if set.
- `initFromMultipleChallenges()` for multi-algorithm negotiation (picks strongest).
- `qop` constructor parameter — defaults to `auth`, set `auth-int` for body integrity.
- `qop=auth-int` hashes request body into HA2.
- Session variant algorithms (`MD5-sess`, `SHA-256-sess`, `SHA-512-256-sess`) with per-nonce HA1 caching.
- `charset=UTF-8` handling with NFC normalization and RFC 5987 `username*` encoding.
- Typed exception hierarchy: `DigestAuthFormatException`, `StaleNonceException`, `AuthenticationException`, `AlgorithmMismatchException`.
- Opaque value echo.
- Stale nonce detection (nonce updated before throw).

### Fixed

- cnonce now uses `Random.secure()` instead of predictable `Random()`.
- Header parser rewritten with quoted-string awareness (handles commas in realm, base64 `=` in nonce).
- Null/empty/non-Digest headers throw instead of returning silently.

## 1.0.1

- Fix: Increment nonces correctly.

## 1.0.0

- Initial version.
- Supports Monero's JSON-RPC API with authentication.
