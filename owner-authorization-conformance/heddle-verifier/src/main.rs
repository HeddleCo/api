use std::{env, fs, process::ExitCode};

use heddle_client::owner_authorization::{
    VerificationLimits, verify_capability_chain, verify_owner_root,
    wire::{SignedOwnerCapability, SignedOwnerRoot},
};
use prost::Message;
use serde::{Deserialize, Serialize};

const NOW: i64 = 1_000;

#[derive(Deserialize)]
struct Corpus {
    signed_owner_root_hex: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    chain_hex: Vec<String>,
}

#[derive(Serialize)]
struct Outcome {
    id: String,
    accepted: bool,
    error: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(outcomes) => {
            println!(
                "{}",
                serde_json::to_string(&outcomes).expect("serialize outcomes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Vec<Outcome>, String> {
    let path = env::args().nth(1).ok_or("missing corpus path")?;
    let corpus: Corpus =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let root: SignedOwnerRoot = decode(&corpus.signed_owner_root_hex)?;
    let state = verify_owner_root(&root).map_err(|error| error.to_string())?;
    let limits =
        VerificationLimits::new(300, 3_600, 1024 * 1024).map_err(|error| error.to_string())?;

    corpus
        .cases
        .into_iter()
        .map(|case| {
            let result = case
                .chain_hex
                .iter()
                .map(|value| decode::<SignedOwnerCapability>(value))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|chain| {
                    verify_capability_chain(&state, &chain, NOW, limits)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                });
            Ok(Outcome {
                id: case.id,
                accepted: result.is_ok(),
                error: result.err(),
            })
        })
        .collect()
}

fn decode<T: Message + Default>(value: &str) -> Result<T, String> {
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    let decoded = T::decode(bytes.as_slice()).map_err(|error| error.to_string())?;
    if decoded.encode_to_vec() != bytes {
        return Err("non-canonical protobuf in corpus".to_string());
    }
    Ok(decoded)
}
