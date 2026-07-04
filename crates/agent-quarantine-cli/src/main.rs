//! Agent Quarantine command-line entry point.
//!
//! One binary plays two roles. Invoked as `agent-quarantine` (or `aq`), it is
//! the normal CLI. Invoked under a shimmed name such as `curl` or `git` — which
//! happens because `run` puts a directory of symlinks to this binary at the
//! front of `PATH` — it enters shim mode and evaluates the intercepted command.

use std::process::ExitCode;

use agent_quarantine_core::command::normalize::basename;

mod cli;
mod commands;

fn main() -> ExitCode {
    let arg0 = std::env::args().next().unwrap_or_default();
    let invoked_as = basename(&arg0);

    // Shim dispatch: only when we were launched under a shimmed name *and* a
    // session is active. Otherwise fall through to the normal CLI.
    if commands::shim::is_shim_name(&invoked_as) && std::env::var_os("AQ_SESSION_ID").is_some() {
        return commands::shim::run_shim(&invoked_as);
    }

    commands::dispatch()
}
