# gkill

fast interactive process killer for linux

## features

- /proc filesystem scanning
- regex pattern matching (case-insensitive by default)
- multi-process selection (`1 3` or `1,3` syntax)
- emergency mode — top 3 ram + top 3 cpu consumers at a glance
- system process warnings (uid=0 processes)
- permission filtering (only shows killable processes)
- race condition protection (verifies process before kill)
- protected pid safety (won't kill init/kthreadd)
- sigterm (default) or sigkill support

## installation

```bash
cargo build --release
sudo cp target/release/gkill /usr/local/bin/
```

## usage

```bash
# search, select, confirm
gkill firefox

# select multiple processes at once
gkill python   # then enter: 1 3  or  1,3  at the prompt

# regex patterns
gkill --regex "chrom(e|ium)"
gkill --regex "python.*server"

# kill all matches (with confirmation)
gkill --all node

# force kill first match without confirmation (requires exactly one match)
gkill --force chrome

# use sigkill instead of sigterm
gkill firefox --sigkill
gkill firefox -9

# emergency mode — shows top 3 ram + top 3 cpu consumers
gkill -e
```

## emergency mode

`gkill -e` scans all your processes and shows the top 6 resource consumers,
labeled by why they appear:

```
top resource consumers:

   1. pid  1234  [me]      [ram+cpu]    3.8 gb   2:14:05  /usr/lib/firefox/firefox
   2. pid  5678  [me]      [ram    ]  512.0 mb   0:01:22  rustc
   3. pid  9012  [me]      [ram    ]  210.3 mb   0:00:04  cliapp
   4. pid  3456  [me]      [cpu    ]   45.0 mb   8:33:11  cargo build --release
   5. pid  7890  [me]      [cpu    ]   12.1 mb   3:02:44  make -j8
```

select one or more to kill, same as normal mode.

## how it works

1. scans /proc for processes matching search string (or all processes in -e mode)
2. filters to processes you can signal (permission check via kill(pid, 0))
3. displays numbered list with pid, owner, and resource info
4. prompts for selection (supports multi-select: `1 3` or `1,3`)
5. warns if any selected process is owned by root
6. confirms before killing (unless --force)
7. verifies process didn't change between selection and kill (toctou protection)
8. sends sigterm or sigkill

## safety

- pids 0–2 (swapper, init, kthreadd) are never shown or killed
- only shows processes you own (unless running as root)
- warns before killing uid=0 processes
- start time verified immediately before kill to prevent pid reuse attacks
- confirmation required by default

## license

use freely
