use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead};

use regex::{Regex, RegexBuilder};

use crate::cli::{Config, Signal};

pub struct ProcessInfo {
    pub pid: u32,
    pub cmdline: String,
    pub uid: u32,
    pub start_time: u64,
    pub is_system: bool,
    pub rss_kb: u64,
    pub cpu_ticks: u64,
}

pub struct EmergencyEntry {
    pub info: ProcessInfo,
    pub is_top_ram: bool,
    pub is_top_cpu: bool,
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

        let Some(info) = collect_process_info(pid, current_uid, current_pid) else {
            continue;
        };

        if !matcher.is_match(&info.cmdline) {
            continue;
        }

        results.push(info);
    }

    results.sort_by_key(|p| p.pid);
    Ok(results)
}

pub fn find_top_processes(current_uid: u32) -> Result<Vec<EmergencyEntry>, String> {
    let mut all: Vec<ProcessInfo> = Vec::new();
    let current_pid = std::process::id();

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
        if let Some(info) = collect_process_info(pid, current_uid, current_pid) {
            all.push(info);
        }
    }

    if all.is_empty() {
        return Ok(Vec::new());
    }

    // top 3 indices by rss
    let mut ram_order: Vec<usize> = (0..all.len()).collect();
    ram_order.sort_unstable_by(|&a, &b| all[b].rss_kb.cmp(&all[a].rss_kb));
    let top_ram: Vec<usize> = ram_order.into_iter().take(3).collect();

    // top 3 indices by cpu
    let mut cpu_order: Vec<usize> = (0..all.len()).collect();
    cpu_order.sort_unstable_by(|&a, &b| all[b].cpu_ticks.cmp(&all[a].cpu_ticks));
    let top_cpu: Vec<usize> = cpu_order.into_iter().take(3).collect();

    let top_ram_set: HashSet<usize> = top_ram.iter().copied().collect();
    let top_cpu_set: HashSet<usize> = top_cpu.iter().copied().collect();

    // merge: ram entries first, then cpu-only entries
    let mut result_indices: Vec<usize> = Vec::with_capacity(6);
    for &i in &top_ram {
        result_indices.push(i);
    }
    for &i in &top_cpu {
        if !top_ram_set.contains(&i) {
            result_indices.push(i);
        }
    }

    let mut by_idx: HashMap<usize, ProcessInfo> = all.into_iter().enumerate().collect();
    let result = result_indices
        .iter()
        .map(|&idx| {
            let info = by_idx.remove(&idx).unwrap();
            EmergencyEntry {
                is_top_ram: top_ram_set.contains(&idx),
                is_top_cpu: top_cpu_set.contains(&idx),
                info,
            }
        })
        .collect();

    Ok(result)
}

pub fn verify_process(pid: u32, original_start_time: u64) -> bool {
    process_stat(pid).map(|(st, _)| st) == Some(original_start_time)
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

fn collect_process_info(pid: u32, current_uid: u32, current_pid: u32) -> Option<ProcessInfo> {
    if pid == current_pid || is_protected_pid(pid) || !can_signal_process(pid) {
        return None;
    }

    let (uid, rss_kb) = process_uid_and_rss(pid)?;

    // non-root users can only signal their own processes
    if current_uid != 0 && uid != current_uid {
        return None;
    }

    let (start_time, cpu_ticks) = process_stat(pid)?;
    let cmdline = read_cmdline(pid)?;

    Some(ProcessInfo {
        pid,
        cmdline,
        uid,
        start_time,
        is_system: uid == 0,
        rss_kb,
        cpu_ticks,
    })
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

fn process_uid_and_rss(pid: u32) -> Option<(u32, u64)> {
    let file = fs::File::open(format!("/proc/{pid}/status")).ok()?;
    let reader = io::BufReader::new(file);
    let mut uid: Option<u32> = None;
    let mut rss_kb: Option<u64> = None;

    for line in reader.lines().map_while(Result::ok) {
        if line.starts_with("Uid:") {
            uid = line.split_whitespace().nth(1)?.parse().ok();
        } else if line.starts_with("VmRSS:") {
            rss_kb = line.split_whitespace().nth(1)?.parse().ok();
        }
        if uid.is_some() && rss_kb.is_some() {
            break;
        }
    }

    Some((uid?, rss_kb.unwrap_or(0)))
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

fn process_stat(pid: u32) -> Option<(u64, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(") ")?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // after ") ": idx 0=state, 11=utime, 12=stime, 19=starttime
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let start_time: u64 = fields.get(19)?.parse().ok()?;
    Some((start_time, utime + stime))
}
