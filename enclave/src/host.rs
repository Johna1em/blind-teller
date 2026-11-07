//! What the pipeline needs from the outside world. OutLayer provides the real
//! one in `main.rs`; tests provide a scripted one.

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait Host {
    fn now_ms(&self) -> u64;
    /// Fill `out` with cryptographically secure random bytes.
    fn random(&self, out: &mut [u8]) -> Result<(), String>;
    /// The verdict key's public half.
    fn verdict_public(&self) -> Result<[u8; 32], String>;
    /// Sign with the verdict key. Only fixed-format messages go through here,
    /// so a caller can never make it sign something of their choosing.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String>;
    fn http(&self, request: HttpRequest) -> Result<HttpResponse, String>;
    /// A secret from the environment.
    fn secret(&self, name: &str) -> Option<String>;
}
