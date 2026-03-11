use base64::Engine;
use olympus_verifier::compute_blake3;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Deserialize)]
struct HashBatchRequest {
    records_b64: Vec<String>,
}

#[derive(Serialize)]
struct HashBatchResponse {
    hashes: Vec<String>,
}

fn main() {
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read stdin: {err}");
        std::process::exit(1);
    }

    let req: HashBatchRequest = match serde_json::from_str(&input) {
        Ok(req) => req,
        Err(err) => {
            eprintln!("failed to parse request JSON: {err}");
            std::process::exit(1);
        }
    };

    let mut hashes = Vec::with_capacity(req.records_b64.len());
    for (idx, record_b64) in req.records_b64.iter().enumerate() {
        let record = match base64::engine::general_purpose::STANDARD.decode(record_b64.as_bytes()) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("invalid base64 at index {idx}: {err}");
                std::process::exit(1);
            }
        };
        hashes.push(hex::encode(compute_blake3(&record)));
    }

    let response = HashBatchResponse { hashes };
    match serde_json::to_string(&response) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("failed to serialize response JSON: {err}");
            std::process::exit(1);
        }
    }
}
