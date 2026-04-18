use hex::FromHex;
use signinwithethereum::{eip55, is_checksum, Message};
use std::str::FromStr;

#[test]
fn parsing() {
    // correct order
    let message = r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#;

    assert!(Message::from_str(message).is_ok());

    assert_eq!(message, &Message::from_str(message).unwrap().to_string());

    // incorrect order
    assert!(Message::from_str(
        r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Nonce: 32891756
Chain ID: 1
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#,
    )
    .is_err());

    //  no statement
    let message = r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2


URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#;

    assert!(Message::from_str(message).is_ok());

    assert_eq!(message, &Message::from_str(message).unwrap().to_string());
}

#[tokio::test]
async fn verification() {
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
    let correct = <[u8; 65]>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();

    let verify_result = message.verify_eip191(&correct);
    dbg!(&verify_result);
    assert!(verify_result.is_ok());

    let incorrect = <[u8; 65]>::from_hex(r#"7228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
    assert!(message.verify_eip191(&incorrect).is_err());
}

#[tokio::test]
async fn verification1() {
    let message = Message::from_str(r#"localhost wants you to sign in with your Ethereum account:
0x4b60ffAf6fD681AbcC270Faf4472011A4A14724C

Allow localhost to access your orbit using their temporary session key: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg

URI: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg
Version: 1
Chain ID: 1
Nonce: PPrtjztx2lYqWbqNs
Issued At: 2021-12-20T12:29:25.907Z
Expiration Time: 2021-12-20T12:44:25.906Z
Resources:
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#put
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#del
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#get
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#list"#).unwrap();
    let correct = <[u8; 65]>::from_hex(r#"20c0da863b3dbfbb2acc0fb3b9ec6daefa38f3f20c997c283c4818ebeca96878787f84fccc25c4087ccb31ebd782ae1d2f74be076a49c0a8604419e41507e9381c"#).unwrap();
    assert!(message.verify_eip191(&correct).is_ok());
    let incorrect = <[u8; 65]>::from_hex(r#"30c0da863b3dbfbb2acc0fb3b9ec6daefa38f3f20c997c283c4818ebeca96878787f84fccc25c4087ccb31ebd782ae1d2f74be076a49c0a8604419e41507e9381c"#).unwrap();
    assert!(message.verify_eip191(&incorrect).is_err());
}

const VALID_CASES: &[&str] = &[
    // From the spec:
    // All caps
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    // All Lower
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
];

const INVALID_CASES: &[&str] = &[
    // From eip55 Crate:
    "0xD1220a0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    "0xdbF03B407c01e7cD3CBea99509d93f8DDDC8C6FB",
    "0xfb6916095ca1df60bB79Ce92cE3Ea74c37c5D359",
    "0x5aAeb6053f3E94C9b9A09f33669435E7Ef1BeAed",
    // FROM SO QUESTION:
    "0xCF5609B003B2776699EEA1233F7C82D5695CC9AA",
    // From eip55 Crate Issue
    "0x000000000000000000000000000000000000dEAD",
];

#[test]
fn test_is_checksum() {
    for case in VALID_CASES {
        let c = case.trim_start_matches("0x");
        assert!(is_checksum(c))
    }

    for case in INVALID_CASES {
        let c = case.trim_start_matches("0x");
        assert!(!is_checksum(c))
    }
}

#[test]
fn eip55_test() {
    // vectors from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md

    assert!(test_eip55(
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    ));
    assert!(test_eip55(
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    ));
    assert!(test_eip55(
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
    ));
    assert!(test_eip55(
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
    ));

    assert!(test_eip55(
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x52908400098527886E0F7030069857D2E4169EE7",
    ));
    assert!(test_eip55(
        "0x8617e340b3d01fa5f11f306f4090fd50e238070d",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    ));
    assert!(test_eip55(
        "0xde709f2102306220921060314715629080e2fb77",
        "0xde709f2102306220921060314715629080e2fb77",
    ));
    assert!(test_eip55(
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        "0x27b1fdb04752bbc536007a920d24acb045561c26"
    ));
    assert!(test_eip55(
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    ));
    assert!(test_eip55(
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    ));
    assert!(test_eip55(
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    ));
    assert!(test_eip55(
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
    ));
}

fn test_eip55(addr: &str, checksum: &str) -> bool {
    let unprefixed = addr.strip_prefix("0x").unwrap();
    eip55(&<[u8; 20]>::from_hex(unprefixed).unwrap()) == checksum
        && eip55(&<[u8; 20]>::from_hex(unprefixed.to_lowercase()).unwrap()) == checksum
        && eip55(&<[u8; 20]>::from_hex(unprefixed.to_uppercase()).unwrap()) == checksum
}

#[test]
fn roundtrip_preserves_unchecksummed_lowercase_address() {
    let msg = "service.org wants you to sign in with your Ethereum account:\n\
0x4a62316623ad457f02cdc5d997ded67a383ec569\n\
\n\
I accept the ServiceOrg Terms of Service: https://service.org/tos\n\
\n\
URI: https://service.org/login\n\
Version: 1\n\
Chain ID: 1\n\
Nonce: abcd1234efgh5678\n\
Issued At: 2026-01-01T00:00:00Z";
    let parsed = Message::from_str(msg).unwrap();
    assert_eq!(parsed.warnings.len(), 1);
    assert_eq!(
        parsed.to_string(),
        msg,
        "Display must emit the original address form so the EIP-191 hash matches what the signer signed"
    );
}

#[test]
fn roundtrip_preserves_unchecksummed_uppercase_address() {
    let msg = "service.org wants you to sign in with your Ethereum account:\n\
0x4A62316623AD457F02CDC5D997DED67A383EC569\n\
\n\
Test\n\
\n\
URI: https://service.org/login\n\
Version: 1\n\
Chain ID: 1\n\
Nonce: abcd1234efgh5678\n\
Issued At: 2026-01-01T00:00:00Z";
    let parsed = Message::from_str(msg).unwrap();
    assert_eq!(parsed.warnings.len(), 1);
    assert_eq!(parsed.to_string(), msg);
}

#[test]
fn verify_unchecksummed_lowercase_address() {
    // Signature produced by deterministic key [7u8; 32] over the lowercase-address
    // message below. Regression guard for https://… (v0.8.0 accepted the message
    // with a warning but always failed verification because Display re-serialized
    // the address as EIP-55 checksummed before hashing.)
    let msg = "service.org wants you to sign in with your Ethereum account:\n\
0x4a62316623ad457f02cdc5d997ded67a383ec569\n\
\n\
I accept the ServiceOrg Terms of Service: https://service.org/tos\n\
\n\
URI: https://service.org/login\n\
Version: 1\n\
Chain ID: 1\n\
Nonce: abcd1234efgh5678\n\
Issued At: 2026-01-01T00:00:00Z";
    let parsed = Message::from_str(msg).unwrap();
    let signature = <[u8; 65]>::from_hex(
        "6932b553cfca65ddf9419a642bd314544b6bc74a84af3fc540b81c18c8b9d8823b2c7ae6853ed5b70da9d14a44a5dba2a32b3ed5635a64b4b57a590e174cf6461b",
    )
    .unwrap();
    parsed.verify_eip191(&signature).expect("verification must succeed for unchecksummed-address message");
}

#[test]
fn reject_non_empty_separator_lines() {
    let base = |sep_after_addr: &str, sep_after_stmt: &str| {
        format!(
            "service.org wants you to sign in with your Ethereum account:\n\
             0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\
             {sep_after_addr}\n\
             I accept the ServiceOrg Terms of Service: https://service.org/tos\n\
             {sep_after_stmt}\n\
             URI: https://service.org/login\n\
             Version: 1\n\
             Chain ID: 1\n\
             Nonce: 32891756\n\
             Issued At: 2021-09-30T16:25:24Z"
        )
    };

    // Canonical form parses fine.
    assert!(Message::from_str(&base("", "")).is_ok());

    // Injected text after address must be rejected.
    let err = Message::from_str(&base("injected line", "")).unwrap_err();
    assert!(
        err.to_string().contains("blank line after address"),
        "unexpected error: {err}"
    );

    // Injected text after statement must be rejected.
    let err = Message::from_str(&base("", "injected line")).unwrap_err();
    assert!(
        err.to_string().contains("blank line after statement"),
        "unexpected error: {err}"
    );

    // No-statement variant: injected text after address.
    let no_stmt = "service.org wants you to sign in with your Ethereum account:\n\
                   0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\n\
                   injected\n\
                   \n\
                   URI: https://service.org/login\n\
                   Version: 1\n\
                   Chain ID: 1\n\
                   Nonce: 32891756\n\
                   Issued At: 2021-09-30T16:25:24Z";
    let err = Message::from_str(no_stmt).unwrap_err();
    assert!(
        err.to_string().contains("blank line after address"),
        "unexpected error: {err}"
    );
}
