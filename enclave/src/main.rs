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
    use wasi::http::outgoing_handler;
    use wasi::http::types::{Fields, Method, OutgoingBody, OutgoingRequest, RequestOptions, Scheme};
    use wasi::io::streams::StreamError;

    const KEY: &str = "verdict";
    /// The most one blocking write may carry. A larger write traps and kills the
    /// run, so a body goes out in pieces. Any email longer than a short receipt
    /// makes a model request bigger than this.
    const MAX_WRITE: usize = 4096;
    const MAX_READ: u64 = 1024 * 1024;

    pub struct OutLayer;

    fn fail(e: impl std::fmt::Debug) -> String {
        format!("{e:?}")
    }

    fn send(request: HttpRequest) -> Result<HttpResponse, String> {
        let rest = request.url.strip_prefix("https://").ok_or("only https is allowed")?;
        let (authority, path) = rest.find('/').map_or((rest, "/"), |slash| rest.split_at(slash));

        let headers = Fields::new();
        for (name, value) in &request.headers {
            headers.set(name, &[value.clone().into_bytes()]).map_err(fail)?;
        }
        let outgoing = OutgoingRequest::new(headers);
        outgoing.set_method(if request.method == "GET" { &Method::Get } else { &Method::Post }).map_err(fail)?;
        outgoing.set_scheme(Some(&Scheme::Https)).map_err(fail)?;
        outgoing.set_authority(Some(authority)).map_err(fail)?;
        outgoing.set_path_with_query(Some(path)).map_err(fail)?;

        let body = outgoing.body().map_err(fail)?;
        {
            let stream = body.write().map_err(fail)?;
            for piece in request.body.chunks(MAX_WRITE) {
                stream.blocking_write_and_flush(piece).map_err(fail)?;
            }
        }
        OutgoingBody::finish(body, None).map_err(fail)?;

        // The worker enforces per-host limits from the manifest. This only
        // bounds the connection.
        let options = RequestOptions::new();
        let connect = Duration::from_secs(request.timeout_secs.min(15));
        options.set_connect_timeout(Some(connect.as_nanos() as u64)).map_err(fail)?;
        let pending = outgoing_handler::handle(outgoing, Some(options)).map_err(fail)?;
        pending.subscribe().block();
        let response = pending.get().ok_or("no response")?.map_err(fail)?.map_err(fail)?;

        let status = response.status();
        let incoming = response.consume().map_err(fail)?;
        let mut out = Vec::new();
        {
            let stream = incoming.stream().map_err(fail)?;
            loop {
                match stream.blocking_read(MAX_READ) {
                    Ok(piece) => out.extend(piece),
                    Err(StreamError::Closed) => break,
                    Err(e) => return Err(fail(e)),
                }
            }
        }
        Ok(HttpResponse { status, body: out })
    }

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
            send(request)
        }

        fn secret(&self, name: &str) -> Option<String> {
            std::env::var(name).ok()
        }

        fn sleep_ms(&self, ms: u64) {
            std::thread::sleep(Duration::from_millis(ms));
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
