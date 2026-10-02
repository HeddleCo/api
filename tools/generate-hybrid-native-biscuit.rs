//! Standalone maintenance helper, never run by tests. Build in an isolated Cargo
//! package with biscuit-auth =6.0.0, heddle-biscuit-verifier =0.28.3, hex =0.4.
//! All seeds are published conformance data. Pass the output .binpb as argv[1].
//! The JavaScript maintenance generator consumes this immutable sealed artifact.
use biscuit_auth::{Biscuit, KeyPair, builder::Algorithm};

fn fixture<T, E: std::fmt::Display>(result: Result<T, E>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}
fn main() -> Result<(), String> {
    let path = std::env::args().nth(1).ok_or("output path required")?;
    let root = fixture(KeyPair::from_bytes(&[2; 32], Algorithm::Ed25519.into()))?;
    let next = fixture(KeyPair::from_bytes(&[14; 32], Algorithm::Ed25519.into()))?;
    let mut builder = Biscuit::builder();
    for fact in [
        "subject(\"21212121-2121-2121-2121-212121212121\")".to_owned(),
        "subject_kind(\"user\")".to_owned(),
        "subject_user_uuid(\"21212121-2121-2121-2121-212121212121\")".to_owned(),
        format!(
            "device_pop_key(\"{}\")",
            hex::encode(root.public().to_bytes())
        ),
        "right(\"spool\", \"example\", \"write\")".to_owned(),
        "issued_at(1970-01-01T00:16:40Z)".to_owned(),
        "expires_at(1970-01-01T00:33:20Z)".to_owned(),
    ] {
        builder = fixture(builder.fact(fact.as_str()))?;
    }
    builder = fixture(builder.check("check if time($now), $now < 1970-01-01T00:33:20Z"))?;
    let token = fixture(
        heddle_biscuit_verifier::signature_v1::build_root_with_key_pair(builder, &root, &next),
    )?;
    let token = fixture(token.seal())?;
    let bytes = fixture(token.to_vec())?;
    fixture(heddle_biscuit_verifier::signature_v1::verify(
        &bytes,
        root.public(),
    ))?;
    fixture(std::fs::write(path, bytes))
}
