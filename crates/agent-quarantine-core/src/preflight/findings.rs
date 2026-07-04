//! Preflight finding and severity types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How serious a preflight finding is. Ordered least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational.
    Low,
    /// Worth a look.
    Medium,
    /// Likely dangerous.
    High,
    /// Almost certainly dangerous.
    Critical,
}

impl Severity {
    /// Stable lowercase name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a severity from a CLI threshold string.
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single issue discovered while scanning a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Kebab-case finding ID.
    pub id: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// File the finding was found in (relative to the scan root).
    pub file: PathBuf,
    /// 1-based line number, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Short title.
    pub title: String,
    /// Longer explanation.
    pub detail: String,
    /// What the user should do about it.
    pub recommendation: String,
}

impl Finding {
    /// Construct a finding.
    pub fn new(
        id: &str,
        severity: Severity,
        file: PathBuf,
        line: Option<usize>,
        title: &str,
        detail: &str,
        recommendation: &str,
    ) -> Self {
        Finding {
            id: id.to_string(),
            severity,
            file,
            line,
            title: title.to_string(),
            detail: detail.to_string(),
            recommendation: recommendation.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_and_parses() {
        assert!(Severity::Critical > Severity::Low);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("nope"), None);
    }
}
