# Sign in with Ethereum

This crate provides a pure Rust implementation of [EIP-4361: Sign In With Ethereum](https://eips.ethereum.org/EIPS/eip-4361).

## Installation

```toml
signinwithethereum = "0.7"
```

### Features

| Feature         | Description                                                                        |
| --------------- | ---------------------------------------------------------------------------------- |
| `serde`         | Serialization/deserialization support                                              |
| `alloy`         | EIP-1271 contract wallet and EIP-6492 counterfactual wallet signature verification |
| `typed-builder` | Builder pattern for `VerificationOpts`                                             |

## Usage

### Parsing a SIWE Message

Parsing is done via the `Message` implementation of `FromStr`:

```rust
# use signinwithethereum::Message;
let msg = "example.com wants you to sign in with your Ethereum account:\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z";
let message: Message = msg.parse().unwrap();
```

The parser validates:

- EIP-55 checksummed address
- Alphanumeric nonce (minimum 8 characters)
- RFC 3339 timestamps
- RFC 3986 URI and domain
- Optional `scheme://` prefix per EIP-4361
- Printable ASCII statement (no control characters)

### Verifying a SIWE Message

Verification and authentication is performed via EIP-191, using the `address` field of the `Message` as the expected signer. This returns the Ethereum public key of the signer:

```rust
# use signinwithethereum::Message;
# use hex::FromHex;
# let msg = "localhost:4361 wants you to sign in with your Ethereum account:\n0x6Da01670d8fc844e736095918bbE11fE8D564163\n\nSIWE Notepad Example\n\nURI: http://localhost:4361\nVersion: 1\nChain ID: 1\nNonce: kEWepMt9knR6lWJ6A\nIssued At: 2021-12-07T18:28:18.807Z";
# let message: Message = msg.parse().unwrap();
# let signature = <[u8; 65]>::from_hex("6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c").unwrap();
let signer: Vec<u8> = message.verify_eip191(&signature).unwrap();
```

Time constraints (expiration and not-before) can be validated at current or specific times:

```rust
# use signinwithethereum::Message;
# use time::OffsetDateTime;
# let msg = "example.com wants you to sign in with your Ethereum account:\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z";
# let message: Message = msg.parse().unwrap();
assert!(message.valid_now());

// equivalent to
assert!(message.valid_at(&OffsetDateTime::now_utc()));
```

Combined verification of time constraints, field bindings, and authentication can be done in a single call with `verify`:

```rust
# use hex::FromHex;
# use signinwithethereum::{Message, VerificationOpts};
# use time::{format_description::well_known::Rfc3339, OffsetDateTime};
# #[tokio::main]
# async fn main() {
# let msg = "localhost:4361 wants you to sign in with your Ethereum account:\n0x6Da01670d8fc844e736095918bbE11fE8D564163\n\nSIWE Notepad Example\n\nURI: http://localhost:4361\nVersion: 1\nChain ID: 1\nNonce: kEWepMt9knR6lWJ6A\nIssued At: 2021-12-07T18:28:18.807Z";
# let message: Message = msg.parse().unwrap();
# let signature = <[u8; 65]>::from_hex("6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c").unwrap();
let opts = VerificationOpts {
    domain: Some("localhost:4361".parse().unwrap()),
    nonce: Some("kEWepMt9knR6lWJ6A".into()),
    timestamp: Some(OffsetDateTime::parse("2021-12-08T00:00:00Z", &Rfc3339).unwrap()),
    ..Default::default()
};
message.verify(&signature, &opts).await.unwrap();
# }
```

### Serialization

`Message` instances serialize as their EIP-4361 string representation via the `Display` trait:

```rust
# use signinwithethereum::Message;
# let msg = "example.com wants you to sign in with your Ethereum account:\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z";
# let message: Message = msg.parse().unwrap();
let formatted = message.to_string();
assert!(formatted.contains("wants you to sign in"));
```

EIP-191 Personal-Signature pre-hash signing input:

```rust
# use signinwithethereum::Message;
# let msg = "example.com wants you to sign in with your Ethereum account:\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z";
# let message: Message = msg.parse().unwrap();
let eip191_bytes: Vec<u8> = message.eip191_bytes().unwrap();
```

EIP-191 Personal-Signature hash (Keccak-256 of the above):

```rust
# use signinwithethereum::Message;
# let msg = "example.com wants you to sign in with your Ethereum account:\n0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z";
# let message: Message = msg.parse().unwrap();
let eip191_hash: [u8; 32] = message.eip191_hash().unwrap();
```

### Smart Contract Wallets (EIP-1271 / EIP-6492)

With the `alloy` feature enabled, `verify()` supports:

- **EIP-1271** -- signature verification for deployed contract wallets (e.g. Safe, Argent)
- **EIP-6492** -- signature verification for counterfactual (not yet deployed) contract wallets

Provide an RPC URL in the verification options. The verification order follows the EIP-6492 specification:

1. **EIP-6492** -- if the signature has the magic suffix, verify via the universal off-chain validator
2. **EOA** -- try standard `ecrecover` for 65-byte signatures
3. **EIP-1271** -- fall back to on-chain `isValidSignature` if EOA verification fails

## Example

```rust
use hex::FromHex;
use signinwithethereum::{Message, TimeStamp, VerificationOpts};
use std::str::FromStr;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[tokio::main]
async fn main() {
    let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#;
    let message: Message = msg.parse().unwrap();
    let signature = <[u8; 65]>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();

    let verification_opts = VerificationOpts {
        domain: Some("localhost:4361".parse().unwrap()),
        nonce: Some("kEWepMt9knR6lWJ6A".into()),
        timestamp: Some(OffsetDateTime::parse("2021-12-08T00:00:00Z", &Rfc3339).unwrap()),
        ..Default::default()
    };

    if let Err(e) = message.verify(&signature, &verification_opts).await {
        println!("Verification failed: {e}");
    }
}
```

## Testing

```bash
cargo test
```

To run tests that require on-chain verification (EIP-1271 / EIP-6492), enable the `alloy` feature and provide an Ethereum mainnet RPC URL:

```bash
ETH_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" cargo test --features alloy
```

## Migrating from `siwe`

This crate is the actively maintained successor to the [`siwe`](https://crates.io/crates/siwe) crate (v0.6), which is no longer maintained.

### Cargo.toml

```diff
- siwe = "0.6"
+ signinwithethereum = "0.7"
```

### Code changes

Rename the import:

```diff
- use siwe::{Message, VerificationOpts};
+ use signinwithethereum::{Message, VerificationOpts};
```

If you used the `ethers` feature for EIP-1271 contract wallet verification, switch to `alloy`:

```diff
- siwe = { version = "0.6", features = ["ethers"] }
+ signinwithethereum = { version = "0.7", features = ["alloy"] }
```

And replace the provider in `VerificationOpts`:

```diff
  let opts = VerificationOpts {
-     rpc_provider: Some("https://eth.llamarpc.com".try_into().unwrap()),
+     rpc_url: Some("https://eth.llamarpc.com".into()),
      ..Default::default()
  };
```

The `Message` struct now has a `scheme: Option<String>` field. If you construct `Message` values directly (rather than parsing), add it:

```diff
  let msg = Message {
+     scheme: None,
      domain: "example.com".parse().unwrap(),
      // ...
  };
```

See [CHANGELOG.md](CHANGELOG.md) for the full list of breaking changes.

## See Also

- [EIP-4361 Specification](https://eips.ethereum.org/EIPS/eip-4361)
- [EIP-191 Specification](https://eips.ethereum.org/EIPS/eip-191)
- [EIP-1271 Specification](https://eips.ethereum.org/EIPS/eip-1271)
- [EIP-6492 Specification](https://eips.ethereum.org/EIPS/eip-6492)
- [Sign in with Ethereum: TypeScript](https://github.com/signinwithethereum/siwe)
