mod cli;
mod procfs;
mod ui;

use std::process;

use cli::{Config, ParseOutcome, parse_args, print_usage};
use procfs::{ProcessInfo, find_processes, find_top_processes, kill_process, verify_process};
use ui::{SelectionOutcome, choose_emergency, choose_processes, print_emergency_matches,
         print_matches, warn_if_system};

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

    if config.emergency {
        let entries = match find_top_processes(current_uid) {
            Ok(e) => e,
            Err(msg) => {
                eprintln!("{msg}");
                process::exit(1);
            }
        };
        if entries.is_empty() {
            println!("no processes found");
            process::exit(0);
        }
        print_emergency_matches(&entries, current_uid);
        let selected = match choose_emergency(&entries, &config) {
            Ok(SelectionOutcome::Selected(s)) => s,
            Ok(SelectionOutcome::Aborted) => {
                println!("aborted");
                process::exit(0);
            }
            Err(msg) => {
                eprintln!("{msg}");
                process::exit(1);
            }
        };
        do_kill(selected, &config);
    } else {
        let matches = match find_processes(&config, current_uid) {
            Ok(m) => m,
            Err(msg) => {
                eprintln!("{msg}");
                process::exit(1);
            }
        };
        if matches.is_empty() {
            println!("no processes found matching '{}'", config.query);
            process::exit(0);
        }
        print_matches(&matches, current_uid);
        let selected = match choose_processes(&matches, &config) {
            Ok(SelectionOutcome::Selected(s)) => s,
            Ok(SelectionOutcome::Aborted) => {
                println!("aborted");
                process::exit(0);
            }
            Err(msg) => {
                eprintln!("{msg}");
                process::exit(1);
            }
        };
        do_kill(selected, &config);
    }
}

fn do_kill(selected: Vec<&ProcessInfo>, config: &Config) {
    for proc in &selected {
        if !verify_process(proc.pid, proc.start_time) {
            eprintln!(
                "process {} changed or disappeared, aborting for safety",
                proc.pid
            );
            process::exit(1);
        }
    }

    // warn about system processes when --force skipped the normal confirm path
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
