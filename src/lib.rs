#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg), feature(doc_cfg))]
#![doc = include_str!("../README.md")]

mod eip6492;
mod nonce;
mod rfc3339;

#[cfg(feature = "alloy")]
mod eip1271;

use ::core::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use hex::FromHex;
use http::uri::{Authority, InvalidUri};
use iri_string::types::UriString;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;
use time::OffsetDateTime;

#[cfg(feature = "serde")]
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

pub use nonce::generate_nonce;
pub use rfc3339::TimeStamp;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// EIP-4361 version.
pub enum Version {
    /// V1
    V1 = 1,
}

impl FromStr for Version {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "1" {
            Ok(Self::V1)
        } else {
            Err(ParseError::Format("Bad Version"))
        }
    }
}

/// EIP-4361 message.
///
/// # Example
/// ```
/// # use signinwithethereum::Message;
/// #
/// let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
/// 0x6Da01670d8fc844e736095918bbE11fE8D564163
///
/// SIWE Notepad Example
///
/// URI: http://localhost:4361
/// Version: 1
/// Chain ID: 1
/// Nonce: kEWepMt9knR6lWJ6A
/// Issued At: 2021-12-07T18:28:18.807Z"#;
/// let message: Message = msg.parse().unwrap();
/// ```
#[derive(Clone, Debug, Eq)]
pub struct Message {
    /// Optional URI scheme of the request origin (e.g. "https").
    pub scheme: Option<String>,
    /// The RFC 3986 authority that is requesting the signing.
    pub domain: Authority,
    /// The Ethereum address performing the signing. Parsed addresses must be EIP-55 checksummed or uniform-case (all-lowercase/all-uppercase); unchecksummed addresses produce a warning.
    pub address: [u8; 20],
    /// A human-readable ASCII assertion that the user will sign, and it must not contain '\n' (the byte 0x0a).
    pub statement: Option<String>,
    /// An RFC 3986 URI referring to the resource that is the subject of the signing (as in the subject of a claim).
    pub uri: UriString,
    /// The current version of the message, which MUST be 1 for this specification.
    pub version: Version,
    /// The EIP-155 Chain ID to which the session is bound, and the network where Contract Accounts MUST be resolved.
    pub chain_id: u64,
    /// A randomized token typically chosen by the relying party and used to prevent replay attacks, at least 8 alphanumeric characters.
    pub nonce: String,
    /// The ISO 8601 datetime string of the current time.
    pub issued_at: TimeStamp,
    /// The ISO 8601 datetime string that, if present, indicates when the signed authentication message is no longer valid.
    pub expiration_time: Option<TimeStamp>,
    /// The ISO 8601 datetime string that, if present, indicates when the signed authentication message will become valid.
    pub not_before: Option<TimeStamp>,
    /// An system-specific identifier that may be used to uniquely refer to the sign-in request.
    pub request_id: Option<String>,
    /// A list of information or references to information the user wishes to have resolved as part of authentication by the relying party. They are expressed as RFC 3986 URIs separated by "\n- " where \n is the byte 0x0a.
    pub resources: Vec<UriString>,
    /// Warnings produced during parsing (e.g., non-EIP-55 checksummed address).
    pub warnings: Vec<String>,
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.scheme == other.scheme
            && self.domain == other.domain
            && self.address == other.address
            && self.statement == other.statement
            && self.uri == other.uri
            && self.version == other.version
            && self.chain_id == other.chain_id
            && self.nonce == other.nonce
            && self.issued_at == other.issued_at
            && self.expiration_time == other.expiration_time
            && self.not_before == other.not_before
            && self.request_id == other.request_id
            && self.resources == other.resources
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        if let Some(scheme) = &self.scheme {
            write!(f, "{}://", scheme)?;
        }
        writeln!(f, "{}{}", &self.domain, PREAMBLE)?;
        writeln!(f, "{}", eip55(&self.address))?;
        writeln!(f)?;
        if let Some(statement) = &self.statement {
            writeln!(f, "{}", statement)?;
            writeln!(f)?;
        } else {
            writeln!(f)?;
        }
        writeln!(f, "{}{}", URI_TAG, &self.uri)?;
        writeln!(f, "{}{}", VERSION_TAG, self.version as u64)?;
        writeln!(f, "{}{}", CHAIN_TAG, &self.chain_id)?;
        writeln!(f, "{}{}", NONCE_TAG, &self.nonce)?;
        write!(f, "{}{}", IAT_TAG, &self.issued_at)?;
        if let Some(exp) = &self.expiration_time {
            write!(f, "\n{}{}", EXP_TAG, &exp)?
        };
        if let Some(nbf) = &self.not_before {
            write!(f, "\n{}{}", NBF_TAG, &nbf)?
        };
        if let Some(rid) = &self.request_id {
            write!(f, "\n{}{}", RID_TAG, rid)?
        };
        if !self.resources.is_empty() {
            write!(f, "\n{}", RES_TAG)?;
            for res in &self.resources {
                write!(f, "\n- {}", res)?;
            }
        };
        Ok(())
    }
}

#[derive(Error, Debug)]
/// Errors raised during parsing/deserialization.
pub enum ParseError {
    #[error("Invalid Domain: {0}")]
    /// Domain field is non-conformant.
    Domain(#[from] InvalidUri),
    #[error("Formatting Error: {0}")]
    /// Catch-all for all other parsing errors.
    Format(&'static str),
    #[error("Invalid Address: {0}")]
    /// Address field is non-conformant.
    Address(#[from] hex::FromHexError),
    #[error("Invalid URI: {0}")]
    /// URI field is non-conformant.
    Uri(#[from] iri_string::validate::Error),
    #[error("Invalid Timestamp: {0}")]
    /// Timestamp is non-conformant.
    TimeStamp(#[from] time::Error),
    #[error(transparent)]
    /// Chain ID is non-conformant.
    ParseIntError(#[from] std::num::ParseIntError),
    #[error(transparent)]
    /// Infallible variant.
    Never(#[from] Infallible),
}

fn tagged<'a>(tag: &'static str, line: Option<&'a str>) -> Result<&'a str, ParseError> {
    line.and_then(|l| l.strip_prefix(tag))
        .ok_or(ParseError::Format(tag))
}

fn parse_line<S: FromStr<Err = E>, E: Into<ParseError>>(
    tag: &'static str,
    line: Option<&str>,
) -> Result<S, ParseError> {
    tagged(tag, line).and_then(|s| S::from_str(s).map_err(|e| e.into()))
}

fn blank_line(line: Option<&str>, context: &'static str) -> Result<(), ParseError> {
    match line {
        Some("") => Ok(()),
        _ => Err(ParseError::Format(context)),
    }
}

fn tag_optional<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<Option<&'a str>, ParseError> {
    match tagged(tag, line).map(Some) {
        Err(ParseError::Format(t)) if t == tag => Ok(None),
        r => r,
    }
}

impl FromStr for Message {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.split('\n');
        let preamble_prefix = lines
            .next()
            .and_then(|preamble| preamble.strip_suffix(PREAMBLE))
            .ok_or(ParseError::Format("Missing Preamble Line"))?;

        // Parse optional scheme://domain prefix per EIP-4361 ABNF.
        let (scheme, domain) = if let Some((scheme_part, rest)) = preamble_prefix.split_once("://")
        {
            // Validate scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
            if !scheme_part
                .bytes()
                .next()
                .map(|b| b.is_ascii_alphabetic())
                .unwrap_or(false)
                || !scheme_part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
            {
                return Err(ParseError::Format("Invalid scheme"));
            }
            (Some(scheme_part.to_string()), Authority::from_str(rest)?)
        } else {
            (None, Authority::from_str(preamble_prefix)?)
        };
        let mut warnings = Vec::new();
        let address_str = tagged(ADDR_TAG, lines.next())?;
        let has_lower = address_str.bytes().any(|b| matches!(b, b'a'..=b'f'));
        let has_upper = address_str.bytes().any(|b| matches!(b, b'A'..=b'F'));
        if has_lower && has_upper && !is_checksum(address_str) {
            return Err(ParseError::Format("Address is not in EIP-55 format"));
        }
        if (has_lower || has_upper) && !(has_lower && has_upper) {
            warnings.push(format!(
                "Address is not EIP-55 checksummed: 0x{}",
                address_str
            ));
        }
        let address = <[u8; 20]>::from_hex(address_str)?;

        blank_line(lines.next(), "Missing blank line after address")?;
        let (statement, uri_line) = match lines.next() {
            None => return Err(ParseError::Format("No lines found after address")),
            Some("") => {
                // Could be missing statement or empty statement.
                // Peek at the next line to distinguish.
                let next = lines.next();
                if next == Some("") {
                    // Three blank lines after address: empty statement.
                    (Some(String::new()), lines.next())
                } else {
                    // Two blank lines after address: missing statement.
                    (None, next)
                }
            }
            Some(s) => {
                // EIP-4361: statement may only contain printable ASCII (0x20-0x7E).
                if !s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                    return Err(ParseError::Format(
                        "Statement contains invalid characters",
                    ));
                }
                blank_line(lines.next(), "Missing blank line after statement")?;
                (Some(s.to_string()), lines.next())
            }
        };

        let uri = parse_line(URI_TAG, uri_line)?;
        let version = parse_line(VERSION_TAG, lines.next())?;
        let chain_id = parse_line(CHAIN_TAG, lines.next())?;
        let nonce = parse_line(NONCE_TAG, lines.next()).and_then(|nonce: String| {
            if nonce.len() < 8 {
                Err(ParseError::Format("Nonce must be at least 8 characters"))
            } else if !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
                Err(ParseError::Format("Nonce must be alphanumeric"))
            } else {
                Ok(nonce)
            }
        })?;
        let issued_at = tagged(IAT_TAG, lines.next())?.parse()?;

        let mut line = lines.next();
        let expiration_time = match tag_optional(EXP_TAG, line)? {
            Some(exp) => {
                line = lines.next();
                Some(exp.parse()?)
            }
            None => None,
        };
        let not_before = match tag_optional(NBF_TAG, line)? {
            Some(nbf) => {
                line = lines.next();
                Some(nbf.parse()?)
            }
            None => None,
        };

        let request_id = match tag_optional(RID_TAG, line)? {
            Some(rid) => {
                line = lines.next();
                Some(rid.into())
            }
            None => None,
        };

        let resources = match line {
            Some(RES_TAG) => lines.map(|s| parse_line("- ", Some(s))).collect(),
            Some(_) => Err(ParseError::Format("Unexpected Content")),
            None => Ok(vec![]),
        }?;

        Ok(Message {
            scheme,
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
            warnings,
        })
    }
}

#[cfg(feature = "serde")]
impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

#[cfg(feature = "serde")]
struct MessageVisitor;

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for MessageVisitor {
    type Value = Message;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an EIP-4361 formatted message")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match Message::from_str(value) {
            Ok(message) => Ok(message),
            Err(error) => Err(E::custom(format!("error parsing message: {}", error))),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Message, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(MessageVisitor)
    }
}

// Fixes the documentation to show the typed builder impl as behind a feature flag.
macro_rules! typed_builder_doc {
    ($struct:item) => {
        #[cfg(feature = "typed-builder")]
        mod tb {
            use super::*;
            #[derive(typed_builder::TypedBuilder)]
            #[builder(doc)]
            #[cfg_attr(docsrs, doc(cfg(all())))]
            $struct
        }

        #[cfg(not(feature = "typed-builder"))]
        mod tb {
            use super::*;
            #[cfg_attr(docsrs, doc(cfg(all())))]
            $struct
        }

        pub use tb::*;
    }
}

typed_builder_doc! {
    /// Verification options and configuration
    pub struct VerificationOpts {
        /// Expected domain field.
        pub domain: Option<Authority>,
        /// Expected nonce field.
        pub nonce: Option<String>,
        /// Datetime for which the message should be valid at.
        pub timestamp: Option<OffsetDateTime>,
        /// Expected URI field.
        pub uri: Option<UriString>,
        /// Expected chain ID.
        pub chain_id: Option<u64>,
        /// Expected scheme field.
        pub scheme: Option<String>,
        #[cfg(feature = "alloy")]
        /// RPC URL for on-chain checks (EIP-1271/EIP-6492 contract wallet signatures).
        pub rpc_url: Option<String>,
    }
}

// Non-derived implementation needed, otherwise the implementation is marked as being behind the
// typed-builder feature flag.
#[allow(clippy::derivable_impls)]
impl Default for VerificationOpts {
    fn default() -> Self {
        Self {
            domain: None,
            nonce: None,
            timestamp: None,
            uri: None,
            chain_id: None,
            scheme: None,
            #[cfg(feature = "alloy")]
            rpc_url: None,
        }
    }
}

#[derive(Error, Debug)]
/// Reasons for the verification of a signed message to fail.
pub enum VerificationError {
    #[error(transparent)]
    /// Signature is not a valid k256 signature.
    Crypto(#[from] k256::ecdsa::Error),
    #[error(transparent)]
    /// Message failed to be serialized.
    Serialization(#[from] fmt::Error),
    #[error("Recovered key does not match address")]
    /// Recovered address does not match the message address.
    Signer,
    #[error("Message is not currently valid")]
    /// Message is not currently valid (expired or not yet valid).
    Time,
    #[error("Message domain does not match")]
    /// Expected message domain does not match.
    DomainMismatch,
    #[error("Message nonce does not match")]
    /// Expected message nonce does not match.
    NonceMismatch,
    #[error("Message URI does not match")]
    /// Expected message URI does not match.
    UriMismatch,
    #[error("Message chain ID does not match")]
    /// Expected message chain ID does not match.
    ChainIdMismatch,
    #[error("Message scheme does not match")]
    /// Expected message scheme does not match.
    SchemeMismatch,
    #[cfg(feature = "alloy")]
    #[error("Contract wallet query failed: {0}")]
    /// Contract wallet or EIP-6492 verification failed unexpectedly.
    ContractCall(String),
    #[cfg(feature = "alloy")]
    #[error("RPC chain ID mismatch: message declares chain {expected}, RPC returned chain {actual}")]
    /// The RPC endpoint serves a different chain than the message declares.
    RpcChainIdMismatch {
        /// Message's declared chain ID.
        expected: u64,
        /// RPC endpoint's chain ID.
        actual: u64,
    },
    #[error("EIP-6492 signature detected but no RPC URL configured")]
    /// An EIP-6492 signature requires an RPC provider for verification.
    RpcRequired,
    #[error("The signature length is invalid for EOA verification and contract wallet support is not enabled")]
    /// The signature is not 65 bytes and the `alloy` feature is not enabled.
    SignatureLength,
}

/// Takes an UNPREFIXED eth address and returns whether it is in checksum format or not.
pub fn is_checksum(address: &str) -> bool {
    match <[u8; 20]>::from_hex(address) {
        Ok(s) => {
            let sum = eip55(&s);
            let sum = sum.trim_start_matches("0x");
            sum == address
        }
        Err(_) => false,
    }
}

impl Message {
    /// Verify the integrity of the message by matching its signature.
    ///
    /// # Arguments
    /// - `sig` - Signature of the message signed by the wallet
    ///
    /// # Example
    /// ```
    /// # use signinwithethereum::Message;
    /// # use hex::FromHex;
    /// #
    /// # let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
    /// # 0x6Da01670d8fc844e736095918bbE11fE8D564163
    /// #
    /// # SIWE Notepad Example
    /// #
    /// # URI: http://localhost:4361
    /// # Version: 1
    /// # Chain ID: 1
    /// # Nonce: kEWepMt9knR6lWJ6A
    /// # Issued At: 2021-12-07T18:28:18.807Z"#;
    /// # let message: Message = msg.parse().unwrap();
    /// let signature = <[u8; 65]>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
    /// let signer: Vec<u8> = message.verify_eip191(&signature).unwrap();
    /// ```
    pub fn verify_eip191(&self, sig: &[u8; 65]) -> Result<Vec<u8>, VerificationError> {
        let prehash = self.eip191_hash()?;
        let signature: Signature = Signature::from_slice(&sig[..64])?;
        let recovery_id = RecoveryId::try_from(&sig[64] % 27)?;

        let pk: VerifyingKey =
            VerifyingKey::recover_from_prehash(&prehash, &signature, recovery_id)?;

        let recovered_address = Keccak256::default()
            .chain_update(&pk.to_encoded_point(false).as_bytes()[1..])
            .finalize();

        let recovered_address: &[u8] = &recovered_address[12..];

        if recovered_address != self.address {
            Err(VerificationError::Signer)
        } else {
            Ok(pk.to_sec1_bytes().to_vec())
        }
    }

    /// Validates time constraints and integrity of the object by matching its signature.
    ///
    /// Verification order follows EIP-6492:
    /// 1. EIP-6492 (counterfactual wallets) — if magic suffix detected
    /// 2. EOA (ecrecover via EIP-191) — for standard 65-byte signatures
    /// 3. EIP-1271 (deployed contract wallets) — fallback if EOA fails
    ///
    /// # Arguments
    /// - `sig` - Signature of the message signed by the wallet
    /// - `opts` - Verification options and configuration
    ///
    /// # Example
    /// ```
    /// # use hex::FromHex;
    /// # use signinwithethereum::{Message, TimeStamp, VerificationOpts};
    /// # use std::str::FromStr;
    /// # use time::{format_description::well_known::Rfc3339, OffsetDateTime};
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// # let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
    /// # 0x6Da01670d8fc844e736095918bbE11fE8D564163
    /// #
    /// # SIWE Notepad Example
    /// #
    /// # URI: http://localhost:4361
    /// # Version: 1
    /// # Chain ID: 1
    /// # Nonce: kEWepMt9knR6lWJ6A
    /// # Issued At: 2021-12-07T18:28:18.807Z"#;
    /// # let message: Message = msg.parse().unwrap();
    /// let signature = <[u8; 65]>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
    ///
    /// let verification_opts = VerificationOpts {
    ///     domain: Some("localhost:4361".parse().unwrap()),
    ///     nonce: Some("kEWepMt9knR6lWJ6A".into()),
    ///     timestamp: Some(OffsetDateTime::parse("2021-12-08T00:00:00Z", &Rfc3339).unwrap()),
    ///     ..Default::default()
    /// };
    ///
    /// message.verify(&signature, &verification_opts).await.unwrap();
    /// # }
    /// ```
    pub async fn verify(
        &self,
        sig: &[u8],
        opts: &VerificationOpts,
    ) -> Result<(), VerificationError> {
        // Time validation
        let time_valid = opts
            .timestamp
            .as_ref()
            .map(|t| self.valid_at(t))
            .unwrap_or_else(|| self.valid_now());
        if !time_valid {
            return Err(VerificationError::Time);
        }

        // Binding checks
        if let Some(d) = &opts.domain {
            if *d != self.domain {
                return Err(VerificationError::DomainMismatch);
            }
        }
        if let Some(n) = &opts.nonce {
            if *n != self.nonce {
                return Err(VerificationError::NonceMismatch);
            }
        }
        if let Some(u) = &opts.uri {
            if *u != self.uri {
                return Err(VerificationError::UriMismatch);
            }
        }
        if let Some(c) = &opts.chain_id {
            if *c != self.chain_id {
                return Err(VerificationError::ChainIdMismatch);
            }
        }
        if let Some(s) = &opts.scheme {
            if self.scheme.as_ref() != Some(s) {
                return Err(VerificationError::SchemeMismatch);
            }
        }

        // Validate RPC chain ID matches the message before any on-chain calls.
        #[cfg(feature = "alloy")]
        if let Some(rpc_url) = &opts.rpc_url {
            use alloy::providers::{Provider, ProviderBuilder};
            let provider = ProviderBuilder::new().connect_http(
                rpc_url.parse().map_err(|e| {
                    VerificationError::ContractCall(format!("Invalid RPC URL: {e}"))
                })?,
            );
            let rpc_chain_id = provider.get_chain_id().await.map_err(|e| {
                VerificationError::ContractCall(format!("Failed to get chain ID: {e}"))
            })?;
            if rpc_chain_id != self.chain_id {
                return Err(VerificationError::RpcChainIdMismatch {
                    expected: self.chain_id,
                    actual: rpc_chain_id,
                });
            }
        }

        // Step 1: EIP-6492 — if signature has the magic suffix, use the universal validator.
        if eip6492::is_eip6492_signature(sig) {
            #[cfg(feature = "alloy")]
            {
                let rpc_url = opts
                    .rpc_url
                    .as_deref()
                    .ok_or(VerificationError::RpcRequired)?;
                let hash = self.eip191_hash()?;
                return if eip6492::verify_eip6492(self.address, hash, sig, rpc_url).await? {
                    Ok(())
                } else {
                    Err(VerificationError::Signer)
                };
            }
            #[cfg(not(feature = "alloy"))]
            return Err(VerificationError::RpcRequired);
        }

        // Step 2: EOA — try standard ecrecover for 65-byte signatures.
        let eoa_result = if sig.len() == 65 {
            self.verify_eip191(sig.try_into().unwrap())
        } else {
            Err(VerificationError::SignatureLength)
        };

        // Step 3: EIP-1271 fallback — if EOA failed and we have an RPC URL, try contract wallet.
        #[cfg(feature = "alloy")]
        if let Err(eoa_err) = eoa_result {
            if let Some(rpc_url) = &opts.rpc_url {
                let hash = self.eip191_hash()?;
                if eip1271::verify_eip1271(self.address, hash, sig, rpc_url).await? {
                    return Ok(());
                }
            }
            return Err(eoa_err);
        }

        eoa_result.map(|_| ())
    }

    /// Validates the time constraints of the message at current time.
    ///
    /// # Example
    /// ```
    /// # use signinwithethereum::Message;
    /// # use time::OffsetDateTime;
    /// #
    /// # let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
    /// # 0x6Da01670d8fc844e736095918bbE11fE8D564163
    /// #
    /// # SIWE Notepad Example
    /// #
    /// # URI: http://localhost:4361
    /// # Version: 1
    /// # Chain ID: 1
    /// # Nonce: kEWepMt9knR6lWJ6A
    /// # Issued At: 2021-12-07T18:28:18.807Z"#;
    /// # let message: Message = msg.parse().unwrap();
    /// assert!(message.valid_now());
    ///
    /// // equivalent to
    /// assert!(message.valid_at(&OffsetDateTime::now_utc()));
    /// ```
    pub fn valid_now(&self) -> bool {
        self.valid_at(&OffsetDateTime::now_utc())
    }

    /// Validates the time constraints of the message at a specific point in time.
    ///
    /// # Arguments
    /// - `t` - timestamp to use when validating time constraints
    ///
    /// # Example
    /// ```
    /// # use signinwithethereum::Message;
    /// # use time::OffsetDateTime;
    /// #
    /// # let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
    /// # 0x6Da01670d8fc844e736095918bbE11fE8D564163
    /// #
    /// # SIWE Notepad Example
    /// #
    /// # URI: http://localhost:4361
    /// # Version: 1
    /// # Chain ID: 1
    /// # Nonce: kEWepMt9knR6lWJ6A
    /// # Issued At: 2021-12-07T18:28:18.807Z"#;
    /// # let message: Message = msg.parse().unwrap();
    /// assert!(message.valid_at(&OffsetDateTime::now_utc()));
    /// ```
    pub fn valid_at(&self, t: &OffsetDateTime) -> bool {
        self.not_before
            .as_ref()
            .map(|nbf| nbf <= t)
            .unwrap_or(true)
            && self
                .expiration_time
                .as_ref()
                .map(|exp| exp > t)
                .unwrap_or(true)
    }

    /// Produces EIP-191 Personal-Signature pre-hash signing input
    ///
    /// # Example
    /// ```
    /// # use signinwithethereum::Message;
    /// #
    /// # let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
    /// # 0x6Da01670d8fc844e736095918bbE11fE8D564163
    /// #
    /// # SIWE Notepad Example
    /// #
    /// # URI: http://localhost:4361
    /// # Version: 1
    /// # Chain ID: 1
    /// # Nonce: kEWepMt9knR6lWJ6A
    /// # Issued At: 2021-12-07T18:28:18.807Z"#;
    /// # let message: Message = msg.parse().unwrap();
    /// let eip191_bytes: Vec<u8> = message.eip191_bytes().unwrap();
    /// ```
    pub fn eip191_bytes(&self) -> Result<Vec<u8>, fmt::Error> {
        let s = self.to_string();
        Ok(format!("\x19Ethereum Signed Message:\n{}{}", s.len(), s).into())
    }

    /// Produces EIP-191 Personal-Signature Hashed signing-input
    ///
    /// # Example
    /// ```
    /// # use signinwithethereum::Message;
    /// #
    /// # let msg = r#"localhost:4361 wants you to sign in with your Ethereum account:
    /// # 0x6Da01670d8fc844e736095918bbE11fE8D564163
    /// #
    /// # SIWE Notepad Example
    /// #
    /// # URI: http://localhost:4361
    /// # Version: 1
    /// # Chain ID: 1
    /// # Nonce: kEWepMt9knR6lWJ6A
    /// # Issued At: 2021-12-07T18:28:18.807Z"#;
    /// # let message: Message = msg.parse().unwrap();
    /// let eip191_hash: [u8; 32] = message.eip191_hash().unwrap();
    /// ```
    pub fn eip191_hash(&self) -> Result<[u8; 32], fmt::Error> {
        Ok(Keccak256::default()
            .chain_update(self.eip191_bytes()?)
            .finalize()
            .into())
    }
}

/// Takes an eth address and returns it as a checksum formatted string.
pub fn eip55(addr: &[u8; 20]) -> String {
    let addr_str = hex::encode(addr);
    let hash = Keccak256::digest(addr_str.as_bytes());
    "0x".chars()
        .chain(addr_str.chars().enumerate().map(|(i, c)| {
            match (c, hash[i >> 1] & if i % 2 == 0 { 128 } else { 8 } != 0) {
                ('a'..='f' | 'A'..='F', true) => c.to_ascii_uppercase(),
                _ => c.to_ascii_lowercase(),
            }
        }))
        .collect()
}

const PREAMBLE: &str = " wants you to sign in with your Ethereum account:";
const ADDR_TAG: &str = "0x";
const URI_TAG: &str = "URI: ";
const VERSION_TAG: &str = "Version: ";
const CHAIN_TAG: &str = "Chain ID: ";
const NONCE_TAG: &str = "Nonce: ";
const IAT_TAG: &str = "Issued At: ";
const EXP_TAG: &str = "Expiration Time: ";
const NBF_TAG: &str = "Not Before: ";
const RID_TAG: &str = "Request ID: ";
const RES_TAG: &str = "Resources:";
