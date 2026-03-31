//! EIP-1271 smart contract wallet signature verification.

use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall,
};

use crate::VerificationError;

sol! {
    /// EIP-1271 `isValidSignature` interface.
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view returns (bytes4);
}

/// EIP-1271 magic return value indicating a valid signature.
const MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// Verify a signature against a deployed contract wallet using EIP-1271.
pub async fn verify_eip1271(
    address: [u8; 20],
    message_hash: [u8; 32],
    signature: &[u8],
    rpc_url: &str,
) -> Result<bool, VerificationError> {
    let provider = ProviderBuilder::new().connect_http(
        rpc_url
            .parse()
            .map_err(|e| VerificationError::ContractCall(format!("Invalid RPC URL: {e}")))?,
    );

    let call = isValidSignatureCall {
        _hash: FixedBytes::from(message_hash),
        _signature: Bytes::copy_from_slice(signature),
    };

    let tx = TransactionRequest::default()
        .to(Address::from(address))
        .input(Bytes::from(call.abi_encode()).into());

    match provider.call(tx).await {
        Ok(result) => Ok(result.len() >= 4 && result[..4] == MAGIC_VALUE),
        // Decoding failures (e.g. contract doesn't implement EIP-1271) → not valid
        Err(_) => Ok(false),
    }
}
