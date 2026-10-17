//! End-to-end encryption in direct messages and groups (dur.io fork)
mod model;
mod ops;

#[cfg(test)]
mod tests;

pub use model::*;
pub use ops::*;
