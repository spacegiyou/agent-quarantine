//! Classify a repository file by name so the scanner can apply the right checks.

use std::path::Path;

/// The category of a file, which selects which detectors run against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, ...).
    AgentInstruction,
    /// Build/package manifests and scripts (package.json, Makefile, ...).
    BuildFile,
    /// MCP server configuration.
    McpConfig,
    /// A shell script.
    ShellScript,
    /// Anything else (skipped by the scanner).
    Other,
}

/// Classify `path` (which may be relative) by its file name and location.
pub fn classify_file(path: &Path) -> FileKind {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let full = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();

    if is_agent_instruction(&name, &full) {
        return FileKind::AgentInstruction;
    }
    if is_mcp_config(&name, &full) {
        return FileKind::McpConfig;
    }
    // Shell scripts are matched by extension before the directory-based build
    // rules so that `scripts/setup.sh` is a ShellScript, not a generic build
    // file (both run the same detectors, but the label should be accurate).
    if name.ends_with(".sh") || name.ends_with(".bash") || name.ends_with(".zsh") {
        return FileKind::ShellScript;
    }
    if is_build_file(&name, &full) {
        return FileKind::BuildFile;
    }
    FileKind::Other
}

fn is_agent_instruction(name: &str, full: &str) -> bool {
    const NAMES: &[&str] = &[
        "agents.md",
        "agents.override.md",
        "claude.md",
        "gemini.md",
        ".cursorrules",
        ".clinerules",
        ".windsurfrules",
        "skill.md",
        "copilot-instructions.md",
    ];
    NAMES.contains(&name)
        || full.contains(".cursor/rules/")
        || full.contains(".claude/")
        || full.contains(".codex/")
        || full.ends_with(".github/copilot-instructions.md")
}

fn is_mcp_config(name: &str, full: &str) -> bool {
    matches!(name, ".mcp.json" | "mcp.json")
        || full.ends_with(".cursor/mcp.json")
        || full.ends_with(".claude/mcp.json")
        || full.ends_with(".vscode/mcp.json")
}

fn is_build_file(name: &str, full: &str) -> bool {
    const NAMES: &[&str] = &[
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.toml",
        "cargo.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "makefile",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
    ];
    NAMES.contains(&name)
        || full.contains(".github/workflows/")
        || full.starts_with("scripts/")
        || full.contains("/scripts/")
        || full.starts_with("bin/")
        || full.contains("/bin/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn classifies_common_files() {
        assert_eq!(
            classify_file(&PathBuf::from("AGENTS.md")),
            FileKind::AgentInstruction
        );
        assert_eq!(
            classify_file(&PathBuf::from("repo/package.json")),
            FileKind::BuildFile
        );
        assert_eq!(
            classify_file(&PathBuf::from(".mcp.json")),
            FileKind::McpConfig
        );
        assert_eq!(
            classify_file(&PathBuf::from("scripts/setup.sh")),
            FileKind::ShellScript
        );
        assert_eq!(
            classify_file(&PathBuf::from("src/main.rs")),
            FileKind::Other
        );
        assert_eq!(
            classify_file(&PathBuf::from(".github/workflows/ci.yml")),
            FileKind::BuildFile
        );
    }
}
