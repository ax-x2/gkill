mod cli;
mod procfs;
mod ui;

use std::process;

use cli::{parse_args, print_usage, ParseOutcome};
use procfs::{find_processes, kill_process, verify_process};
use ui::{choose_processes, print_matches, warn_if_system, SelectionOutcome};

fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(ParseOutcome::Help) => {
            print_usage();
            process::exit(0);
        }
        Err(ParseOutcome::Message(message)) => {
            eprintln!("{message}");
            print_usage();
            process::exit(1);
        }
    };

    let current_uid = unsafe { libc::getuid() };

    let matches = match find_processes(&config, current_uid) {
        Ok(matches) => matches,
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    };
    if matches.is_empty() {
        println!("no processes found matching '{}'", config.query);
        process::exit(0);
    }

    print_matches(&matches, current_uid);

    let selected = match choose_processes(&matches, &config) {
        Ok(SelectionOutcome::Selected(selected)) => selected,
        Ok(SelectionOutcome::Aborted) => {
            println!("aborted");
            process::exit(0);
        }
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    };

    for proc in &selected {
        if !verify_process(proc.pid, proc.start_time) {
            eprintln!(
                "process {} changed or disappeared, aborting for safety",
                proc.pid
            );
            process::exit(1);
        }
    }

    // warn about system processes when --force skipped the normal confirm path.
    if config.force {
        warn_if_system(&selected);
    }

    for proc in selected {
        if let Err(err) = kill_process(proc.pid, config.signal) {
            eprintln!("failed to kill process {}: {}", proc.pid, err);
            process::exit(1);
        }
    }
}
