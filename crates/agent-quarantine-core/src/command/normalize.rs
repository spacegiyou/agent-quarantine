//! Normalize a raw intercepted command into a structured [`CommandAttempt`].
//!
//! Normalization is deliberately small and readable (per the spec, "prefer
//! small readable checks with tests over one giant regex"). It extracts the
//! executable basename, keeps the original arguments, and exposes the handful
//! of derived views the classifier needs: the display string, and — for shell
//! interpreters invoked with `-c` — the inner script, which is where most
//! compound danger actually lives.

use std::path::Path;

/// The known POSIX-ish shell interpreters we look inside when they are called
/// with `-c "<script>"`.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "ash"];

/// A single command an agent tried to run, as seen by a shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandAttempt {
    /// The executable basename, e.g. `curl` (never the full path).
    pub program: String,
    /// The arguments passed after the program name.
    pub args: Vec<String>,
}

impl CommandAttempt {
    /// Build an attempt from a program name and its arguments.
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        let program = basename(&program.into());
        CommandAttempt { program, args }
    }

    /// Build an attempt from a full argv where `argv[0]` is the program (path
    /// or name). Returns `None` if the argv is empty.
    pub fn from_argv(argv: &[String]) -> Option<Self> {
        let (first, rest) = argv.split_first()?;
        Some(CommandAttempt::new(first.clone(), rest.to_vec()))
    }

    /// A single display string, `program arg1 arg2 ...`. This is for humans and
    /// for substring matching; it is not shell-safe quoting.
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }

    /// True if the program is a shell interpreter.
    pub fn is_shell(&self) -> bool {
        SHELLS.contains(&self.program.as_str())
    }

    /// If this is a shell invoked with `-c <script>`, return the script.
    pub fn shell_c_script(&self) -> Option<&str> {
        if !self.is_shell() {
            return None;
        }
        let mut iter = self.args.iter();
        while let Some(arg) = iter.next() {
            if arg == "-c" {
                return iter.next().map(String::as_str);
            }
            // Handle bundled flags like `-lc` where `c` still expects a script.
            if arg.starts_with('-') && arg.len() > 1 && arg.ends_with('c') && !arg.contains("--") {
                return iter.next().map(String::as_str);
            }
        }
        None
    }

    /// The set of strings the classifier scans: always the display string, plus
    /// the inner script when the program is `sh -c "..."`. Scanning the script
    /// is what lets us catch `curl ... | sh` and friends.
    pub fn haystacks(&self) -> Vec<String> {
        let mut out = vec![self.display()];
        if let Some(script) = self.shell_c_script() {
            out.push(script.to_string());
        }
        out
    }
}

/// Return the final path component of a program string.
pub fn basename(program: &str) -> String {
    Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_strips_directories() {
        assert_eq!(basename("/usr/bin/curl"), "curl");
        assert_eq!(basename("curl"), "curl");
        assert_eq!(basename("./scripts/setup.sh"), "setup.sh");
    }

    #[test]
    fn from_argv_splits_program_and_args() {
        let argv = vec!["/bin/git".to_string(), "status".to_string()];
        let attempt = CommandAttempt::from_argv(&argv).unwrap();
        assert_eq!(attempt.program, "git");
        assert_eq!(attempt.args, vec!["status"]);
        assert!(CommandAttempt::from_argv(&[]).is_none());
    }

    #[test]
    fn detects_shell_c_script() {
        let attempt = CommandAttempt::new("bash", vec!["-c".into(), "echo hi".into()]);
        assert!(attempt.is_shell());
        assert_eq!(attempt.shell_c_script(), Some("echo hi"));
    }

    #[test]
    fn detects_bundled_shell_c_flag() {
        let attempt = CommandAttempt::new("sh", vec!["-lc".into(), "echo hi".into()]);
        assert_eq!(attempt.shell_c_script(), Some("echo hi"));
    }

    #[test]
    fn non_shell_has_no_script() {
        let attempt = CommandAttempt::new("curl", vec!["https://example.invalid".into()]);
        assert!(!attempt.is_shell());
        assert_eq!(attempt.shell_c_script(), None);
    }

    #[test]
    fn haystacks_include_script() {
        let attempt = CommandAttempt::new("sh", vec!["-c".into(), "curl x | sh".into()]);
        let hay = attempt.haystacks();
        assert!(hay.iter().any(|h| h.contains("curl x | sh")));
    }
}
