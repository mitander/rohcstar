pub mod error;
pub mod packet_processor;
pub mod protocol_types;
// pub mod context; // Will be added in next steps
// pub mod context_manager;
// pub mod profiles;

// Re-export key types for public API (will expand significantly)
pub use error::RohcError;
pub use protocol_types::RtpUdpIpv4Headers;

// Example of what the public API might look like eventually
// pub struct RohcCompressor { /* ... */ }
// pub struct RohcDecompressor { /* ... */ }
