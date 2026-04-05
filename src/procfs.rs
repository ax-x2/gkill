use regex::{Regex, RegexBuilder};
use std::fs;
use std::io::{self, BufRead};

use crate::cli::{Config, Signal};

pub struct ProcessInfo {
    pub pid: u32,
    pub cmdline: String,
    pub uid: u32,
    pub start_time: u64,
    pub is_system: bool,
}

pub fn find_processes(config: &Config, current_uid: u32) -> Result<Vec<ProcessInfo>, String> {
    let mut results = Vec::new();
    let current_pid = std::process::id();
    let matcher = build_matcher(&config.query, config.use_regex)?;

    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(err) => return Err(format!("failed to read /proc: {err}")),
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();

        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        if pid == current_pid || is_protected_pid(pid) || !can_signal_process(pid) {
            continue;
        }

        let Some(uid) = process_uid(pid) else {
            continue;
        };

        // non-root users can only signal their own processes; skip others early.
        if current_uid != 0 && uid != current_uid {
            continue;
        }

        let Some(start_time) = process_start_time(pid) else {
            continue;
        };

        let Some(cmdline) = read_cmdline(pid) else {
            continue;
        };

        if !matcher.is_match(&cmdline) {
            continue;
        }

        results.push(ProcessInfo {
            pid,
            cmdline,
            uid,
            start_time,
            is_system: uid == 0,
        });
    }

    results.sort_by_key(|p| p.pid);
    Ok(results)
}

pub fn verify_process(pid: u32, original_start_time: u64) -> bool {
    process_start_time(pid) == Some(original_start_time)
}

pub fn kill_process(pid: u32, signal: Signal) -> io::Result<()> {
    unsafe {
        if libc::kill(pid as i32, signal.as_raw()) == 0 {
            println!("sent {} to process {}", signal_name(signal), pid);
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

pub fn signal_name(signal: Signal) -> &'static str {
    match signal {
        Signal::Kill => "SIGKILL",
        Signal::Term => "SIGTERM",
    }
}

enum Matcher {
    Literal(String),
    Regex(Regex),
}

impl Matcher {
    fn is_match(&self, input: &str) -> bool {
        match self {
            Self::Literal(pattern) => input.to_lowercase().contains(pattern.as_str()),
            Self::Regex(regex) => regex.is_match(input),
        }
    }
}

fn build_matcher(query: &str, use_regex: bool) -> Result<Matcher, String> {
    if use_regex {
        RegexBuilder::new(query)
            .case_insensitive(true)
            .build()
            .map(Matcher::Regex)
            .map_err(|err| format!("invalid regex '{query}': {err}"))
    } else {
        Ok(Matcher::Literal(query.to_lowercase()))
    }
}

#[inline]
fn is_protected_pid(pid: u32) -> bool {
    matches!(pid, 0..=2)
}

#[inline]
fn can_signal_process(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn process_uid(pid: u32) -> Option<u32> {
    let file = fs::File::open(format!("/proc/{pid}/status")).ok()?;
    let reader = io::BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        if line.starts_with("Uid:") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

fn read_cmdline(pid: u32) -> Option<String> {
    let cmdline_path = format!("/proc/{pid}/cmdline");
    let comm_path = format!("/proc/{pid}/comm");

    if let Ok(data) = fs::read(&cmdline_path)
        && !data.is_empty()
    {
        let mut cmdline = String::with_capacity(data.len());
        for segment in data.split(|&b| b == 0).filter(|s| !s.is_empty()) {
            if !cmdline.is_empty() {
                cmdline.push(' ');
            }
            cmdline.push_str(&String::from_utf8_lossy(segment));
        }
        if !cmdline.is_empty() {
            return Some(cmdline);
        }
    }

    fs::read_to_string(comm_path)
        .ok()
        .map(|comm| comm.trim().to_string())
        .filter(|comm| !comm.is_empty())
}

fn process_start_time(pid: u32) -> Option<u64> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(stat_path).ok()?;
    let (_, rest) = stat.rsplit_once(") ")?;
    rest.split_whitespace().nth(19)?.parse::<u64>().ok()
}
