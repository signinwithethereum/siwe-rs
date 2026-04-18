use hex::FromHex;
use iri_string::types::UriString;
use signinwithethereum::{is_checksum, Message, TimeStamp, VerificationOpts, Version};
use std::str::FromStr;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const PARSING_POSITIVE: &str =
    include_str!("../test-vectors/vectors/parsing/parsing_positive.json");
const PARSING_NEGATIVE: &str =
    include_str!("../test-vectors/vectors/parsing/parsing_negative.json");
const VERIFICATION_POSITIVE: &str =
    include_str!("../test-vectors/vectors/verification/verification_positive.json");
const VERIFICATION_NEGATIVE: &str =
    include_str!("../test-vectors/vectors/verification/verification_negative.json");
#[cfg(feature = "alloy")]
const VERIFICATION_EIP1271: &str =
    include_str!("../test-vectors/vectors/verification/eip1271.json");

// Grammar test vectors
const GRAMMAR_VALID_URIS: &str =
    include_str!("../test-vectors/vectors/grammar/valid_uris.json");
const GRAMMAR_INVALID_URIS: &str =
    include_str!("../test-vectors/vectors/grammar/invalid_uris.json");
const GRAMMAR_VALID_RESOURCES: &str =
    include_str!("../test-vectors/vectors/grammar/valid_resources.json");
const GRAMMAR_INVALID_RESOURCES: &str =
    include_str!("../test-vectors/vectors/grammar/invalid_resources.json");
const GRAMMAR_VALID_SPECIFICATION: &str =
    include_str!("../test-vectors/vectors/grammar/valid_specification.json");

// Parsing warning test vectors
const PARSING_WARNINGS: &str =
    include_str!("../test-vectors/vectors/parsing/parsing_warnings.json");

// Object test vectors
const OBJECT_MESSAGE_OBJECTS: &str =
    include_str!("../test-vectors/vectors/objects/message_objects.json");
const OBJECT_PARSING_NEGATIVE: &str =
    include_str!("../test-vectors/vectors/objects/parsing_negative_objects.json");

/// Returns the hex string verbatim when the input is not EIP-55 checksummed
/// (uniform-case), so that `Message::address_raw` is set consistently with what
/// the parser would populate from an equivalent message string.
fn unchecksummed_raw(address_hex: &str) -> Option<String> {
    let has_lower = address_hex.bytes().any(|b| matches!(b, b'a'..=b'f'));
    let has_upper = address_hex.bytes().any(|b| matches!(b, b'A'..=b'F'));
    if (has_lower || has_upper) && !(has_lower && has_upper) {
        Some(address_hex.to_string())
    } else {
        None
    }
}

fn fields_to_message(fields: &serde_json::Value) -> anyhow::Result<Message> {
    let fields = fields.as_object().unwrap();
    let address_hex = fields["address"]
        .as_str()
        .unwrap()
        .strip_prefix("0x")
        .unwrap();
    Ok(Message {
        scheme: fields
            .get("scheme")
            .and_then(|s| s.as_str())
            .map(String::from),
        domain: fields["domain"].as_str().unwrap().try_into().unwrap(),
        address: <[u8; 20]>::from_hex(address_hex).unwrap(),
        address_raw: unchecksummed_raw(address_hex),
        statement: fields
            .get("statement")
            .map(|s| s.as_str().unwrap().try_into().unwrap()),
        uri: fields["uri"].as_str().unwrap().try_into().unwrap(),
        version: <Version as std::str::FromStr>::from_str(fields["version"].as_str().unwrap())
            .unwrap(),
        chain_id: fields["chainId"].as_u64().unwrap(),
        nonce: fields["nonce"].as_str().unwrap().try_into().unwrap(),
        issued_at: <TimeStamp as std::str::FromStr>::from_str(
            fields["issuedAt"].as_str().unwrap(),
        )?,
        expiration_time: match fields.get("expirationTime") {
            Some(e) => Some(<TimeStamp as std::str::FromStr>::from_str(
                e.as_str().unwrap(),
            )?),
            None => None,
        },
        not_before: if let Some(not_before) = fields.get("notBefore") {
            Some(<TimeStamp as std::str::FromStr>::from_str(
                not_before.as_str().unwrap(),
            )?)
        } else {
            None
        },
        request_id: fields
            .get("requestId")
            .map(|e| e.as_str().unwrap().to_string()),
        resources: fields
            .get("resources")
            .map(|e| {
                e.as_array()
                    .unwrap()
                    .iter()
                    .map(|r| {
                        <UriString as std::str::FromStr>::from_str(r.as_str().unwrap()).unwrap()
                    })
                    .collect()
            })
            .unwrap_or_default(),
        warnings: vec![],
    })
}

/// Try to construct a Message from a JSON field object, performing the same
/// validations as the string parser (EIP-55, nonce, URI, timestamps, etc.).
fn try_message_from_object(obj: &serde_json::Value) -> Result<Message, String> {
    let fields = obj.as_object().ok_or("not an object")?;

    let domain_str = fields
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or("missing domain")?;
    let domain = http::uri::Authority::from_str(domain_str)
        .map_err(|_| "invalid domain".to_string())?;

    let address_str = fields
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or("missing address")?;
    let address_hex = address_str
        .strip_prefix("0x")
        .ok_or("address missing 0x prefix")?;
    let mut warnings = Vec::new();
    let has_lower = address_hex.bytes().any(|b| matches!(b, b'a'..=b'f'));
    let has_upper = address_hex.bytes().any(|b| matches!(b, b'A'..=b'F'));
    if has_lower && has_upper && !is_checksum(address_hex) {
        return Err("invalid EIP-55 address".into());
    }
    if (has_lower || has_upper) && !(has_lower && has_upper) {
        warnings.push(format!(
            "Address is not EIP-55 checksummed: {}",
            address_str
        ));
    }
    let address_raw = unchecksummed_raw(address_hex);
    let address =
        <[u8; 20]>::from_hex(address_hex).map_err(|_| "invalid address hex".to_string())?;

    let statement = fields
        .get("statement")
        .and_then(|v| v.as_str())
        .map(String::from);

    let uri_str = fields
        .get("uri")
        .and_then(|v| v.as_str())
        .ok_or("missing uri")?;
    let uri = <UriString as std::str::FromStr>::from_str(uri_str)
        .map_err(|_| "invalid uri".to_string())?;

    let version_str = fields
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or("missing version")?;
    let version =
        Version::from_str(version_str).map_err(|_| "invalid version".to_string())?;

    let chain_id = fields
        .get("chainId")
        .and_then(|v| v.as_u64())
        .ok_or("missing or invalid chainId")?;

    let nonce_str = fields
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or("missing nonce")?;
    if nonce_str.len() < 8 {
        return Err("nonce too short".into());
    }
    if !nonce_str.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("nonce not alphanumeric".into());
    }
    let nonce = nonce_str.to_string();

    let issued_at_str = fields
        .get("issuedAt")
        .and_then(|v| v.as_str())
        .ok_or("missing issuedAt")?;
    let issued_at: TimeStamp = issued_at_str
        .parse()
        .map_err(|_| "invalid issuedAt".to_string())?;

    let expiration_time = match fields.get("expirationTime").and_then(|v| v.as_str()) {
        Some(s) => Some(
            s.parse::<TimeStamp>()
                .map_err(|_| "invalid expirationTime".to_string())?,
        ),
        None => None,
    };

    let not_before = match fields.get("notBefore").and_then(|v| v.as_str()) {
        Some(s) => Some(
            s.parse::<TimeStamp>()
                .map_err(|_| "invalid notBefore".to_string())?,
        ),
        None => None,
    };

    let request_id = fields
        .get("requestId")
        .and_then(|v| v.as_str())
        .map(String::from);

    let resources = match fields.get("resources") {
        Some(arr) => {
            let arr = arr.as_array().ok_or("resources not array")?;
            arr.iter()
                .map(|r| {
                    let s = r.as_str().ok_or("resource not string")?;
                    <UriString as std::str::FromStr>::from_str(s)
                        .map_err(|_| "invalid resource URI".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?
        }
        None => vec![],
    };

    Ok(Message {
        scheme: None,
        domain,
        address,
        address_raw,
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

#[test]
fn parsing_positive() {
    let tests: serde_json::Value = serde_json::from_str(PARSING_POSITIVE).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let parsed_message = Message::from_str(test["message"].as_str().unwrap()).unwrap();
        let fields = &test["fields"];
        let expected_message = fields_to_message(fields).unwrap();
        assert!(parsed_message == expected_message);
        println!("✅")
    }
}

#[test]
fn parsing_negative() {
    let tests: serde_json::Value = serde_json::from_str(PARSING_NEGATIVE).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        assert!(Message::from_str(test.as_str().unwrap()).is_err());
        println!("✅")
    }
}

#[test]
fn parsing_warnings() {
    let tests: serde_json::Value = serde_json::from_str(PARSING_WARNINGS).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let parsed_message = Message::from_str(test["message"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", test_name, e));
        let fields = &test["fields"];
        let expected_message = fields_to_message(fields).unwrap();
        assert_eq!(parsed_message, expected_message, "{}: fields", test_name);
        let expected_warnings = test["expectedWarnings"].as_u64().unwrap() as usize;
        assert_eq!(
            parsed_message.warnings.len(),
            expected_warnings,
            "{}: warnings count",
            test_name
        );
        println!("✅")
    }
}

#[tokio::test]
async fn verification_positive() {
    let tests: serde_json::Value = serde_json::from_str(VERIFICATION_POSITIVE).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let fields = &test;
        let message = fields_to_message(fields).unwrap();
        let signature = <[u8; 65]>::from_hex(
            fields.as_object().unwrap()["signature"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let timestamp = fields
            .as_object()
            .unwrap()
            .get("time")
            .and_then(|timestamp| {
                OffsetDateTime::parse(timestamp.as_str().unwrap(), &Rfc3339).ok()
            });
        let opts = VerificationOpts {
            timestamp,
            ..Default::default()
        };
        assert!(message.verify(&signature, &opts).await.is_ok());
        println!("✅")
    }
}

#[cfg(feature = "alloy")]
#[tokio::test]
#[ignore = "requires ETH_RPC_URL env var and network access"]
async fn verification_eip1271() {
    let tests: serde_json::Value = serde_json::from_str(VERIFICATION_EIP1271).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let message = Message::from_str(test["message"].as_str().unwrap()).unwrap();
        let signature = <Vec<u8>>::from_hex(
            test["signature"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let rpc_url =
            std::env::var("ETH_RPC_URL").expect("ETH_RPC_URL must be set to run EIP-1271 tests");
        let opts = VerificationOpts {
            rpc_url: Some(rpc_url),
            ..Default::default()
        };
        assert!(message.verify(&signature, &opts).await.is_ok());
        println!("✅")
    }
}

#[cfg(feature = "alloy")]
#[tokio::test]
async fn rpc_chain_id_mismatch() {
    use signinwithethereum::VerificationError;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    // Spin up a fake RPC that always returns chain ID 137 (Polygon).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            // Return chain 137 regardless of request.
            let body = r#"{"jsonrpc":"2.0","id":1,"result":"0x89"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });

    // Message declares chain ID 1, but our RPC returns 137.
    let message = Message::from_str(
        r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
    )
    .unwrap();

    let sig = <[u8; 65]>::from_hex(
        "6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb\
         679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c",
    )
    .unwrap();

    let opts = VerificationOpts {
        rpc_url: Some(format!("http://127.0.0.1:{port}")),
        ..Default::default()
    };

    let err = message.verify(&sig, &opts).await.unwrap_err();
    assert!(
        matches!(
            err,
            VerificationError::RpcChainIdMismatch {
                expected: 1,
                actual: 137
            }
        ),
        "expected RpcChainIdMismatch, got: {err:?}"
    );
}

#[tokio::test]
async fn verification_negative() {
    let tests: serde_json::Value = serde_json::from_str(VERIFICATION_NEGATIVE).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let fields = &test;
        let message = fields_to_message(fields);
        let signature = <Vec<u8>>::from_hex(
            fields.as_object().unwrap()["signature"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        );
        let domain_binding = fields
            .as_object()
            .unwrap()
            .get("domainBinding")
            .and_then(|domain_binding| {
                http::uri::Authority::from_str(domain_binding.as_str().unwrap()).ok()
            });
        let match_nonce = fields
            .as_object()
            .unwrap()
            .get("matchNonce")
            .and_then(|match_nonce| match_nonce.as_str())
            .map(|n| n.to_string());
        let timestamp = fields
            .as_object()
            .unwrap()
            .get("time")
            .and_then(|timestamp| {
                OffsetDateTime::parse(timestamp.as_str().unwrap(), &Rfc3339).ok()
            });
        #[allow(clippy::needless_update)]
        let opts = VerificationOpts {
            domain: domain_binding,
            nonce: match_nonce,
            timestamp,
            ..Default::default()
        };
        assert!(
            message.is_err()
                || signature.is_err()
                || message
                    .unwrap()
                    .verify(&signature.unwrap(), &opts)
                    .await
                    .is_err()
        );
        println!("✅")
    }
}

#[test]
fn grammar_valid_uris() {
    let tests: serde_json::Value = serde_json::from_str(GRAMMAR_VALID_URIS).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        // iri_string correctly rejects leading zeros in IPv4 dec-octets per RFC 3986 ABNF
        // (dec-octet does not allow leading zeros), while the TS ABNF parser is lenient.
        if test_name == "IPv4address leading zeros: uri://[::000.000.010.001]"
            || test_name == "IPv4address max value: uri://[::001.099.200.255]"
        {
            continue;
        }
        print!("{} -> ", test_name);
        let message = Message::from_str(test["msg"].as_str().unwrap());
        assert!(
            message.is_ok(),
            "Failed to parse valid URI message: {}",
            test_name
        );
        println!("✅")
    }
}

#[test]
fn grammar_invalid_uris() {
    let tests: serde_json::Value = serde_json::from_str(GRAMMAR_INVALID_URIS).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        assert!(
            Message::from_str(test.as_str().unwrap()).is_err(),
            "Should have rejected invalid URI message: {}",
            test_name
        );
        println!("✅")
    }
}

#[test]
fn grammar_valid_resources() {
    let tests: serde_json::Value = serde_json::from_str(GRAMMAR_VALID_RESOURCES).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let message = Message::from_str(test["msg"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", test_name, e));
        let expected: Vec<&str> = test["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert_eq!(message.resources.len(), expected.len(), "{}", test_name);
        for (i, exp) in expected.iter().enumerate() {
            assert_eq!(
                message.resources[i].to_string(),
                *exp,
                "resource[{}] mismatch for: {}",
                i,
                test_name
            );
        }
        println!("✅")
    }
}

#[test]
fn grammar_invalid_resources() {
    let tests: serde_json::Value = serde_json::from_str(GRAMMAR_INVALID_RESOURCES).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        assert!(
            Message::from_str(test.as_str().unwrap()).is_err(),
            "Should have rejected invalid resource message: {}",
            test_name
        );
        println!("✅")
    }
}

#[test]
fn grammar_valid_specification() {
    let tests: serde_json::Value = serde_json::from_str(GRAMMAR_VALID_SPECIFICATION).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let message = Message::from_str(test["msg"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", test_name, e));
        let items = test["items"].as_object().unwrap();
        for (field, expected) in items {
            match field.as_str() {
                "statement" => {
                    if expected.is_null() {
                        assert_eq!(message.statement, None, "{}: statement", test_name);
                    } else {
                        assert_eq!(
                            message.statement.as_deref(),
                            Some(expected.as_str().unwrap()),
                            "{}: statement",
                            test_name
                        );
                    }
                }
                "requestId" => {
                    if expected.is_null() {
                        assert_eq!(
                            message.request_id, None,
                            "{}: requestId",
                            test_name
                        );
                    } else {
                        assert_eq!(
                            message.request_id.as_deref(),
                            Some(expected.as_str().unwrap()),
                            "{}: requestId",
                            test_name
                        );
                    }
                }
                "resources" => {
                    if expected.is_null() {
                        assert!(
                            message.resources.is_empty(),
                            "{}: resources should be empty",
                            test_name
                        );
                    } else {
                        let exp: Vec<&str> = expected
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|r| r.as_str().unwrap())
                            .collect();
                        assert_eq!(
                            message.resources.len(),
                            exp.len(),
                            "{}: resources length",
                            test_name
                        );
                        for (i, e) in exp.iter().enumerate() {
                            assert_eq!(
                                message.resources[i].to_string(),
                                *e,
                                "{}: resources[{}]",
                                test_name,
                                i
                            );
                        }
                    }
                }
                _ => panic!("Unknown specification field: {}", field),
            }
        }
        println!("✅")
    }
}

#[test]
fn object_message_objects() {
    let tests: serde_json::Value = serde_json::from_str(OBJECT_MESSAGE_OBJECTS).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        let result = try_message_from_object(&test["msg"]);
        let expected_error = test["error"].as_str().unwrap();
        if expected_error == "none" {
            let msg = result.unwrap_or_else(|e| {
                panic!("Expected success for {}: {:?}", test_name, e)
            });
            let expected_warnings = test
                .get("expectedWarnings")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            assert_eq!(
                msg.warnings.len(),
                expected_warnings,
                "{}: warnings count",
                test_name
            );
        } else {
            assert!(
                result.is_err(),
                "Expected error for {}: constructed successfully",
                test_name
            );
        }
        println!("✅")
    }
}

#[test]
fn object_parsing_negative() {
    let tests: serde_json::Value = serde_json::from_str(OBJECT_PARSING_NEGATIVE).unwrap();
    for (test_name, test) in tests.as_object().unwrap() {
        print!("{} -> ", test_name);
        assert!(
            try_message_from_object(test).is_err(),
            "Expected error for negative object: {}",
            test_name
        );
        println!("✅")
    }
}
