# Changelog

## Unreleased

### Breaking Changes

- **Added `warnings` field to `Message`** — The `Message` struct now includes `warnings: Vec<String>` to carry parsing warnings (e.g., non-EIP-55 checksummed addresses). Code constructing `Message` values directly will need to provide this field. The `PartialEq` implementation excludes `warnings` from equality checks, so two messages differing only in warnings are considered equal.

### Changed

- **Unchecksummed addresses now accepted with warning** — All-lowercase and all-uppercase Ethereum addresses are now accepted during parsing (with a warning in `Message::warnings`), matching the TypeScript reference implementation. Mixed-case addresses with an invalid checksum are still rejected. Previously, all non-checksummed addresses were rejected.
- **Empty statements now distinguished from missing** — The parser now correctly handles the three statement states defined by EIP-4361: present (`Some("text")`), empty (`Some("")`), and missing (`None`). Previously, empty and missing were conflated.

### Added

- **Grammar test vectors** — Added grammar validation tests for URIs, resources, and specification fields from the official SIWE test vector suite.
- **Object test vectors** — Added object construction tests (message objects and parsing negative) to validate field-level constraints (EIP-55, nonce length, timestamps) independent of string parsing.
- **Parsing warning test vectors** — Added tests for EIP-55 address warning behavior (all-lowercase, all-uppercase).

## 0.7.1

### Fixed

- **Cross-chain contract-wallet verification** — Fixed EIP-1271/EIP-6492 verification when the message's chain ID differs from the RPC endpoint. The RPC chain ID is now validated against the message before any on-chain calls.
- **Blank line injection** — The parser now enforces that separator lines between the address, statement, and URI fields are truly blank. Non-empty lines in separator positions are rejected.

## 0.7.0

### Breaking Changes

- **Replaced `ethers` feature with `alloy`** — The `ethers` optional dependency (deprecated, unmaintained) has been replaced with `alloy` v1. The `VerificationOpts` field `rpc_provider: Option<Provider<Http>>` is now `rpc_url: Option<String>`. Users passing an ethers `Provider` should pass the RPC URL string instead.
- **Added `scheme` field to `Message`** — The `Message` struct now includes `scheme: Option<String>` to support the optional URI scheme prefix defined in EIP-4361 (e.g. `https://example.com wants you to sign in...`). Code constructing `Message` values directly will need to provide this field.
- **Fixed temporal boundary semantics** — `valid_at()` now uses the half-open interval `[not_before, expiration_time)`, matching the TypeScript reference implementation. Previously it used `(not_before, expiration_time]`, which was inverted: messages were invalid at their exact `not_before` time and valid at their exact `expiration_time`. Both boundaries are now correct.
- **Nonce validation is stricter** — The parser now rejects nonces containing non-alphanumeric characters, enforcing the EIP-4361 ABNF requirement `nonce = 8*( ALPHA / DIGIT )`.
- **Statement validation is stricter** — The parser now rejects statements containing control characters or non-printable ASCII, enforcing EIP-4361's character set restriction.
- **New `VerificationOpts` fields** — Added `uri: Option<UriString>`, `chain_id: Option<u64>`, and `scheme: Option<String>` for binding verification during `verify()`.
- **New error variants** — `VerificationError` now includes `UriMismatch`, `ChainIdMismatch`, `SchemeMismatch`, and `RpcRequired`.
- **Rust edition updated** — Minimum edition is now 2021 (was 2018).
- **Dependency upgrades** — `rand` 0.8 -> 0.10, `thiserror` 1.0 -> 2.0, `typed-builder` 0.14 -> 0.23.

### Added

- **EIP-6492 support** — Signatures from counterfactual (not yet deployed) smart contract wallets are now supported. When the `alloy` feature is enabled and an `rpc_url` is provided, `verify()` detects the EIP-6492 magic suffix and uses the universal off-chain validator contract to verify the signature without requiring the wallet to be deployed.
- **Verification order follows EIP-6492 spec** — `verify()` now checks signatures in the correct order: EIP-6492 (if magic suffix present) -> EOA via EIP-191 -> EIP-1271 fallback.
- **URI, chain ID, and scheme binding checks** — `verify()` can now validate that the message's `uri`, `chain_id`, and `scheme` match expected values, bringing parity with the TypeScript reference implementation.

### Fixed

- **Scheme parsing** — Messages with the optional `scheme://` prefix (e.g. `https://example.com wants you to sign in...`) are now parsed correctly instead of being rejected.
- **Temporal boundaries** — See breaking changes above. Messages are now valid at their `not_before` time and invalid at their `expiration_time`, matching standard interval semantics.
- **Test vectors restored** — The official SIWE test vector suite (parsing positive/negative, verification positive/negative, EIP-1271) is now included and runs as part of `cargo test`.

## 0.6.1

Last release by Spruce Systems, Inc.
