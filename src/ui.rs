use std::io::{self, BufRead, Write};

use crate::cli::{Config, Signal};
use crate::procfs::{signal_name, ProcessInfo};

pub enum SelectionOutcome<'a> {
    Selected(Vec<&'a ProcessInfo>),
    Aborted,
}

pub fn print_matches(matches: &[ProcessInfo], current_uid: u32) {
    for (idx, proc) in matches.iter().enumerate() {
        let owner = if proc.uid == current_uid {
            "me".to_string()
        } else {
            format!("uid:{}", proc.uid)
        };

        println!(
            "{}. PID {} [{}] - {}",
            idx + 1,
            proc.pid,
            owner,
            truncate(&proc.cmdline, 100)
        );
    }
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
                "--force requires exactly one match, found {}. Use --all or narrow the pattern.",
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
        "send {} to PID {} ({})? [y/N]: ",
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
                "warning: PID {} ({}) is owned by root — system process, proceed with caution",
                proc.pid,
                truncate(&proc.cmdline, 60)
            );
        }
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    let mut chars = s.chars();
    let mut out: String = chars.by_ref().take(max_len).collect();
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}
