# gkill

fast process killer with grep-based search

## features

- /proc filesystem scanning
- regex pattern matching (case-insensitive by default)
- permission filtering (only shows killable processes)
- race condition protection
- protected pid safety (wont kill init/systemd)
- sigterm (default) or sigkill support

## installation

```bash
cargo build --release
sudo cp target/release/gkill /usr/local/bin/
```

## usage

```bash
# interactive mode - search, select, confirm
gkill firefox

# regex patterns supported
gkill "chrom(e|ium)"
gkill "python.*server"

# force mode - kills first match without confirmation
gkill --force chrome

# use sigkill instead of sigterm
gkill firefox --sigkill
gkill firefox -9

# combine flags
gkill --force --sigkill stuck_process
```

## how it works

1. scans /proc for processes matching search string
2. filters out processes you cant kill (permission check)
3. displays numbered list with pid and owner
4. prompts for selection and confirmation (unless --force)
5. verifies process didnt change before killing (race protection)
6. sends sigterm or sigkill

## safety features

- protected pids (1, 2) cannot be killed
- only shows processes you own (unless root)
- verifies process cmdline before kill
- requires confirmation by default

## license

use freely
