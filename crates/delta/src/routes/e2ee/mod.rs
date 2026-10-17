//! End-to-end encryption: device keys, to-device mailbox, key backup (dur.io fork)
//!
//! Routes are mounted under `/e2ee` (BE-06 and later).
mod guard;

#[allow(unused_imports)]
pub use guard::E2eeSession;
