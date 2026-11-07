//! OutLayer entry point: stdin JSON in, stdout JSON out.
//!
//! This file is the only place that touches the host. Build for hardware with
//! `cargo build -p blind-teller-enclave --target wasm32-wasip2 --release --features wasi`.

use std::io::{Read, Write};

use enclave::pipeline;

/// Embedded so it's covered by the wasm hash: nobody can widen the network
/// allowlist without changing the code's identity.
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] = *include_bytes!("../manifest.json");

#[cfg(feature = "wasi")]
mod host {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use enclave::host::{Host, HttpRequest, HttpResponse};
    use outlayer::signing_keys;
    use wasi_http_client::Client;

    const KEY: &str = "verdict";

    pub struct OutLayer;

    impl Host for OutLayer {
        fn now_ms(&self) -> u64 {
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
        }

        fn random(&self, out: &mut [u8]) -> Result<(), String> {
            getrandom::getrandom(out).map_err(|e| e.to_string())
        }

        fn verdict_public(&self) -> Result<[u8; 32], String> {
            let key = signing_keys::public_key(KEY, None).map_err(|e| format!("{e:?}"))?;
            key.try_into().map_err(|_| "bad key length".to_string())
        }

        fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
            let signature = signing_keys::sign(KEY, None, message).map_err(|e| format!("{e:?}"))?;
            signature.try_into().map_err(|_| "bad signature length".to_string())
        }

        fn http(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            let client = Client::new();
            let mut builder = match request.method {
                "GET" => client.get(&request.url),
                _ => client.post(&request.url),
            };
            for (name, value) in &request.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            // The worker enforces per-host limits from the manifest; this only
            // bounds the connection.
            builder = builder.connect_timeout(Duration::from_secs(request.timeout_secs.min(15)));
            if !request.body.is_empty() {
                builder = builder.body(&request.body);
            }
            let response = builder.send().map_err(|e| e.to_string())?;
            let status = response.status();
            Ok(HttpResponse { status, body: response.body().map_err(|e| e.to_string())? })
        }

        fn secret(&self, name: &str) -> Option<String> {
            std::env::var(name).ok()
        }
    }
}

fn main() {
    let mut input = Vec::new();
    let output = match std::io::stdin().read_to_end(&mut input) {
        Ok(_) => answer(&input),
        Err(_) => serde_json::json!({ "ok": false, "code": "bad_input" }),
    };
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(output.to_string().as_bytes());
    let _ = stdout.flush();
}

#[cfg(feature = "wasi")]
fn answer(input: &[u8]) -> serde_json::Value {
    pipeline::run(&host::OutLayer, input)
}

#[cfg(not(feature = "wasi"))]
fn answer(_: &[u8]) -> serde_json::Value {
    let _ = pipeline::run;
    serde_json::json!({ "ok": false, "code": "built_without_host" })
}
