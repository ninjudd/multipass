//! Off macOS there is no Touch ID or Apple Watch to approve a request, so
//! no session agent starts, and every command asks for the passphrase.

use std::time::Duration;

/// How a request for approval ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Approved,
    Denied,
    Unavailable,
}

pub struct TouchId;

impl TouchId {
    pub fn available() -> bool {
        false
    }

    pub fn approve(_reason: &str, _timeout: Duration) -> Approval {
        Approval::Unavailable
    }
}
