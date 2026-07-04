//! Command handling: normalize an intercepted command into a [`CommandAttempt`],
//! classify it against the deterministic rule set, and resolve the real
//! executable behind a shim.

pub mod classify;
pub mod executable;
pub mod normalize;

pub use classify::classify;
pub use executable::resolve_real_executable;
pub use normalize::CommandAttempt;
