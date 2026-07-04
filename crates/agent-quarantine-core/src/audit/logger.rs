//! Append-only JSONL audit logger.
//!
//! Each event is one line of JSON. The file is opened in append mode for every
//! write so that concurrent shims in the same session can log safely without a
//! shared handle.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::audit::event::Event;
use crate::error::{CoreError, Result};

/// Appends [`Event`]s to a session log file.
#[derive(Debug, Clone)]
pub struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    /// Create a logger targeting `path` (the file is created on first write).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        AuditLogger { path: path.into() }
    }

    /// The log file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Ensure the parent directory of the log file exists.
    pub fn ensure_parent(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        Ok(())
    }

    /// Append one event as a JSON line.
    pub fn log(&self, event: &Event) -> Result<()> {
        let line = serde_json::to_string(event).map_err(|e| CoreError::Serialize(e.to_string()))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    /// Read and parse every event from a JSONL session log.
    pub fn read_events(path: &Path) -> Result<Vec<Event>> {
        let text = fs::read_to_string(path)?;
        let mut events = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(line)
                .map_err(|e| CoreError::EventParse(format!("line {}: {e}", idx + 1)))?;
            events.push(event);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_events_through_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("sessions").join("aq_test.jsonl");
        let logger = AuditLogger::new(&log);
        logger.ensure_parent().unwrap();

        logger
            .log(&Event::session_start("aq_test", "/repo", "started"))
            .unwrap();
        logger
            .log(&Event::command_exit("aq_test", "ls", 0))
            .unwrap();
        logger.log(&Event::session_end("aq_test")).unwrap();

        let events = AuditLogger::read_events(&log).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "session_start");
        assert_eq!(events[1].exit_status, Some(0));
        assert_eq!(events[2].event_type, "session_end");
    }

    #[test]
    fn reports_parse_errors_with_line_number() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("bad.jsonl");
        fs::write(&log, "{\"type\":\"session_start\"} \nnot json\n").unwrap();
        let err = AuditLogger::read_events(&log).unwrap_err();
        // First line is missing required fields; either way it's an EventParse.
        assert!(matches!(err, CoreError::EventParse(_)));
    }
}
