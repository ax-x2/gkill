use std::io::{self, BufRead, Write};

use crate::cli::{Config, Signal};
use crate::procfs::{EmergencyEntry, ProcessInfo, signal_name};

pub enum SelectionOutcome<'a> {
    Selected(Vec<&'a ProcessInfo>),
    Aborted,
}

pub fn print_matches(matches: &[ProcessInfo], current_uid: u32) {
    for (idx, proc) in matches.iter().enumerate() {
        let owner = owner_label(proc.uid, current_uid);
        println!(
            "{}. pid {} [{}] - {}",
            idx + 1,
            proc.pid,
            owner,
            truncate(&proc.cmdline, 100)
        );
    }
}

pub fn print_emergency_matches(entries: &[EmergencyEntry], current_uid: u32) {
    println!("top resource consumers:\n");

    let pid_w = entries
        .iter()
        .map(|e| e.info.pid.to_string().len())
        .max()
        .unwrap_or(1);
    let owner_w = entries
        .iter()
        .map(|e| owner_label(e.info.uid, current_uid).len())
        .max()
        .unwrap_or(2);

    for (idx, entry) in entries.iter().enumerate() {
        let tag = match (entry.is_top_ram, entry.is_top_cpu) {
            (true, true) => "ram+cpu",
            (true, false) => "ram    ",
            (false, true) => "cpu    ",
            (false, false) => "       ",
        };
        let owner = owner_label(entry.info.uid, current_uid);
        println!(
            "  {:>2}. pid {:>pid_w$}  [{:<owner_w$}]  [{}]  {:>9}  {:>9}  {}",
            idx + 1,
            entry.info.pid,
            owner,
            tag,
            format_rss(entry.info.rss_kb),
            format_cpu(entry.info.cpu_ticks),
            truncate(&entry.info.cmdline, 60),
        );
    }
    println!();
}

pub fn choose_processes<'a>(
    matches: &'a [ProcessInfo],
    config: &Config,
) -> Result<SelectionOutcome<'a>, String> {
    if config.kill_all {
        let selected: Vec<&ProcessInfo> = matches.iter().collect();
        if !config.force && !confirm_bulk_kill(&selected, config.signal)? {
            return Ok(SelectionOutcome::Aborted);
        }
        return Ok(SelectionOutcome::Selected(selected));
    }

    if config.force {
        if matches.len() != 1 {
            return Err(format!(
                "--force requires exactly one match, found {}. use --all or narrow the pattern.",
                matches.len()
            ));
        }
        return Ok(SelectionOutcome::Selected(vec![&matches[0]]));
    }

    if matches.len() == 1 {
        let selected = &matches[0];
        if !confirm_single_kill(selected, config.signal)? {
            return Ok(SelectionOutcome::Aborted);
        }
        return Ok(SelectionOutcome::Selected(vec![selected]));
    }

    let Some(indices) = prompt_selection(matches.len())? else {
        return Ok(SelectionOutcome::Aborted);
    };
    let selected: Vec<&ProcessInfo> = indices.iter().map(|&i| &matches[i - 1]).collect();
    if !confirm_bulk_kill(&selected, config.signal)? {
        return Ok(SelectionOutcome::Aborted);
    }

    Ok(SelectionOutcome::Selected(selected))
}

pub fn choose_emergency<'a>(
    entries: &'a [EmergencyEntry],
    config: &Config,
) -> Result<SelectionOutcome<'a>, String> {
    if config.kill_all {
        let selected: Vec<&ProcessInfo> = entries.iter().map(|e| &e.info).collect();
        if !config.force && !confirm_bulk_kill(&selected, config.signal)? {
            return Ok(SelectionOutcome::Aborted);
        }
        return Ok(SelectionOutcome::Selected(selected));
    }

    if config.force {
        if entries.len() != 1 {
            return Err(format!(
                "--force requires exactly one match, found {}. use --all or narrow the pattern.",
                entries.len()
            ));
        }
        return Ok(SelectionOutcome::Selected(vec![&entries[0].info]));
    }

    let Some(indices) = prompt_selection(entries.len())? else {
        return Ok(SelectionOutcome::Aborted);
    };
    let selected: Vec<&ProcessInfo> = indices.iter().map(|&i| &entries[i - 1].info).collect();
    if !confirm_bulk_kill(&selected, config.signal)? {
        return Ok(SelectionOutcome::Aborted);
    }

    Ok(SelectionOutcome::Selected(selected))
}

/// returns indices (1-based) of selected processes, or None if aborted.
/// retries up to 3 times on invalid input.
fn prompt_selection(len: usize) -> Result<Option<Vec<usize>>, String> {
    for attempt in 0..3 {
        if attempt > 0 {
            eprintln!("invalid input, try again ({} attempt(s) left)", 3 - attempt);
        }
        print!("\nselect processes to kill (1-{len}, e.g. \"1 3\" or \"1,3\", q to abort): ");
        io::stdout().flush().map_err(|e| e.to_string())?;

        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;

        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("q") {
            return Ok(None);
        }

        let tokens: Vec<&str> = trimmed
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.is_empty() {
            continue;
        }

        let mut indices = Vec::with_capacity(tokens.len());
        let mut valid = true;
        for token in &tokens {
            match token.parse::<usize>() {
                Ok(n) if n >= 1 && n <= len => {
                    if !indices.contains(&n) {
                        indices.push(n);
                    }
                }
                _ => {
                    valid = false;
                    break;
                }
            }
        }

        if valid && !indices.is_empty() {
            indices.sort_unstable();
            return Ok(Some(indices));
        }
    }

    Err("too many invalid attempts, aborting".to_string())
}

fn confirm_single_kill(proc: &ProcessInfo, signal: Signal) -> Result<bool, String> {
    warn_if_system(&[proc]);
    print!(
        "send {} to pid {} ({})? [y/N]: ",
        signal_name(signal),
        proc.pid,
        truncate(&proc.cmdline, 80)
    );
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut confirm = String::new();
    io::stdin()
        .lock()
        .read_line(&mut confirm)
        .map_err(|e| e.to_string())?;

    Ok(confirm.trim().eq_ignore_ascii_case("y"))
}

fn confirm_bulk_kill(selected: &[&ProcessInfo], signal: Signal) -> Result<bool, String> {
    warn_if_system(selected);
    print!(
        "send {} to {} process(es)? [y/N]: ",
        signal_name(signal),
        selected.len()
    );
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut confirm = String::new();
    io::stdin()
        .lock()
        .read_line(&mut confirm)
        .map_err(|e| e.to_string())?;

    Ok(confirm.trim().eq_ignore_ascii_case("y"))
}

pub fn warn_if_system(procs: &[&ProcessInfo]) {
    for proc in procs {
        if proc.is_system {
            eprintln!(
                "warning: pid {} ({}) is owned by root — system process, proceed with caution",
                proc.pid,
                truncate(&proc.cmdline, 60)
            );
        }
    }
}

fn owner_label(uid: u32, current_uid: u32) -> String {
    if uid == current_uid {
        "me".to_string()
    } else {
        format!("uid:{uid}")
    }
}

fn format_rss(rss_kb: u64) -> String {
    if rss_kb >= 1024 * 1024 {
        format!("{:.1} gb", rss_kb as f64 / (1024.0 * 1024.0))
    } else if rss_kb >= 1024 {
        format!("{:.1} mb", rss_kb as f64 / 1024.0)
    } else {
        format!("{rss_kb} kb")
    }
}

fn format_cpu(ticks: u64) -> String {
    let secs = ticks / 100; // USER_HZ = 100
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h}:{m:02}:{s:02}")
}

fn truncate(s: &str, max_len: usize) -> String {
    let mut chars = s.chars();
    let mut out: String = chars.by_ref().take(max_len).collect();
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}
