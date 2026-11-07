//! The Blind Teller enclave: pure logic, testable on any machine. `main.rs`
//! wires it to OutLayer; everything else stays free of the host.

pub mod checks;
#[cfg(feature = "dev-extractor")]
pub mod devrules;
pub mod dkim;
pub mod e2ee;
pub mod host;
pub mod mime;
pub mod nearai;
pub mod pipeline;
pub mod policy;
pub mod seal;
