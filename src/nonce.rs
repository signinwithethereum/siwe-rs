use rand::distr::Alphanumeric;
use rand::{rng, RngExt};

/// Generates a secure nonce.
pub fn generate_nonce() -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(17)
        .map(char::from)
        .collect()
}
