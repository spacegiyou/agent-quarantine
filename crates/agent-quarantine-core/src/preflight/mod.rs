//! Preflight: scan a repository *before* letting an agent work in it, looking
//! for risky install scripts, prompt-injected agent instructions, dangerous MCP
//! configs, and suspicious shell patterns.

pub mod file_kinds;
pub mod findings;
pub mod scanner;

pub use file_kinds::FileKind;
pub use findings::{Finding, Severity};
pub use scanner::{scan_path, ScanOptions};
