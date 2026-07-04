//! Centralized secret redaction.
//!
//! Everything that could reach a log, report, snapshot, or error message passes
//! through here first. We never emit an original secret value. The placeholder
//! is always `[REDACTED]`.

use once_cell::sync::Lazy;
use regex::Regex;

/// Substrings (case-insensitive) that mark a name as sensitive.
const SENSITIVE_NAMES: &[&str] = &[
    "TOKEN",
    "KEY",
    "SECRET",
    "PASSWORD",
    "PASS",
    "CREDENTIAL",
    "AUTH",
    "COOKIE",
    "SESSION",
];

/// Flags whose *following* argument is a secret value.
const SENSITIVE_FLAGS: &[&str] = &[
    "--token",
    "--api-key",
    "--apikey",
    "--password",
    "--secret",
    "--authorization",
    "--auth",
    "--access-token",
    "--client-secret",
    "-u",
    "--user",
];

/// Known secret-token prefixes we can redact with high confidence.
const KEY_PREFIXES: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "glpat-",
    "AKIA",
    "AIza",
];

const PLACEHOLDER: &str = "[REDACTED]";

static BEARER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)bearer\s+\S+").expect("valid regex"));

/// `NAME=VALUE` where NAME contains a sensitive marker, anywhere in a string.
static ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    let names = SENSITIVE_NAMES.join("|").to_ascii_lowercase();
    Regex::new(&format!(
        "(?i)([A-Za-z_][A-Za-z0-9_-]*(?:{names})[A-Za-z0-9_-]*)=([^\\s&\"']+)"
    ))
    .expect("valid regex")
});

/// `"name": "value"` JSON-ish pairs where the name contains a sensitive marker.
static JSON_RE: Lazy<Regex> = Lazy::new(|| {
    let names = SENSITIVE_NAMES.join("|").to_ascii_lowercase();
    Regex::new(&format!(
        "(?i)(\"[A-Za-z0-9_-]*(?:{names})[A-Za-z0-9_-]*\")(\\s*:\\s*)\"[^\"]*\""
    ))
    .expect("valid regex")
});

/// Basic-auth credentials passed with `-u`/`--user` inside a single string.
static BASIC_AUTH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(-u|--user)(=|\s+)\S+").expect("valid regex"));

/// Known secret-token prefixes appearing anywhere in a string.
static PREFIX_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    let prefixes = KEY_PREFIXES.join("|");
    Regex::new(&format!(r"(?:{prefixes})[A-Za-z0-9_-]{{6,}}")).expect("valid regex")
});

/// Redact a single argument, then truncate it to `max_len` characters.
///
/// Redaction is pattern-based over the whole string (not just a whole-arg
/// value), so a secret embedded inside a `sh -c` script, a URL query, or a JSON
/// body is caught rather than logged in cleartext.
pub fn redact_arg(arg: &str, max_len: usize) -> String {
    // Whole private-key blocks.
    if arg.contains("PRIVATE KEY") && arg.contains("BEGIN") {
        return "[REDACTED PRIVATE KEY]".to_string();
    }

    let mut s = arg.to_string();
    s = ASSIGN_RE.replace_all(&s, "${1}=[REDACTED]").into_owned();
    s = JSON_RE
        .replace_all(&s, "${1}${2}\"[REDACTED]\"")
        .into_owned();
    s = BASIC_AUTH_RE
        .replace_all(&s, "${1}${2}[REDACTED]")
        .into_owned();
    s = BEARER_RE.replace_all(&s, "Bearer [REDACTED]").into_owned();
    s = PREFIX_TOKEN_RE.replace_all(&s, PLACEHOLDER).into_owned();

    truncate(&s, max_len)
}

/// Redact a full argument vector, accounting for `--flag <secret>` pairs.
pub fn redact_argv(argv: &[String], max_len: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;
    for arg in argv {
        if redact_next {
            out.push(PLACEHOLDER.to_string());
            redact_next = false;
            continue;
        }
        if SENSITIVE_FLAGS.contains(&arg.as_str()) {
            out.push(arg.clone());
            redact_next = true;
            continue;
        }
        out.push(redact_arg(arg, max_len));
    }
    out
}

fn truncate(s: &str, max_len: usize) -> String {
    if max_len == 0 || s.chars().count() <= max_len {
        return s.to_string();
    }
    let cut: String = s.chars().take(max_len).collect();
    format!("{cut}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    // All test secrets below are obviously fake and never executed.
    const FAKE: &str = "FAKE0000000000000000";

    #[test]
    fn redacts_key_value_assignments() {
        assert_eq!(
            redact_arg(&format!("API_TOKEN={FAKE}"), 500),
            "API_TOKEN=[REDACTED]"
        );
        assert_eq!(
            redact_arg(&format!("AWS_SECRET_ACCESS_KEY={FAKE}"), 500),
            "AWS_SECRET_ACCESS_KEY=[REDACTED]"
        );
        // Non-sensitive names are left alone.
        assert_eq!(redact_arg("LANG=en_US.UTF-8", 500), "LANG=en_US.UTF-8");
    }

    #[test]
    fn redacts_flag_value_pairs() {
        let argv = vec![
            "curl".to_string(),
            "--token".to_string(),
            FAKE.to_string(),
            "https://example.invalid".to_string(),
        ];
        let out = redact_argv(&argv, 500);
        assert_eq!(out[1], "--token");
        assert_eq!(out[2], "[REDACTED]");
        assert!(!out.iter().any(|a| a.contains(FAKE)));
    }

    #[test]
    fn redacts_bearer_and_prefixed_tokens() {
        let redacted = redact_arg(&format!("Authorization: Bearer {FAKE}"), 500);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains(FAKE));
        assert_eq!(redact_arg("ghp_FAKE000000000000", 500), "[REDACTED]");
    }

    #[test]
    fn redacts_private_key_block() {
        let arg = "-----BEGIN OPENSSH PRIVATE KEY-----FAKE-----END-----";
        assert_eq!(redact_arg(arg, 500), "[REDACTED PRIVATE KEY]");
    }

    #[test]
    fn truncates_long_values() {
        let long = "a".repeat(50);
        let out = redact_arg(&long, 10);
        assert_eq!(out, format!("{}...", "a".repeat(10)));
    }

    #[test]
    fn redacts_basic_auth_pair_across_args() {
        let argv = vec![
            "curl".to_string(),
            "-u".to_string(),
            "alice:s3cr3tpass".to_string(),
            "https://example.invalid".to_string(),
        ];
        let out = redact_argv(&argv, 500);
        assert_eq!(out[2], "[REDACTED]");
        assert!(!out.iter().any(|a| a.contains("s3cr3tpass")));
    }

    #[test]
    fn redacts_secret_embedded_in_shell_script() {
        // A whole `sh -c` script is one argument; the secret inside must still
        // be redacted rather than logged in cleartext.
        let script = "curl -u admin:hunter2secret https://example.invalid";
        let out = redact_arg(script, 500);
        assert!(!out.contains("hunter2secret"), "basic-auth leaked: {out}");
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_token_embedded_in_url_and_json() {
        let url = "https://api.example.invalid/?apikey=sk-FAKE0123456789&page=2";
        let out = redact_arg(url, 500);
        assert!(
            !out.contains("sk-FAKE0123456789"),
            "url token leaked: {out}"
        );
        assert!(out.contains("page=2"), "over-redacted: {out}");

        let json = "{\"api_key\":\"sk-FAKE0123456789\"}";
        let out = redact_arg(json, 500);
        assert!(
            !out.contains("sk-FAKE0123456789"),
            "json token leaked: {out}"
        );
    }
}
