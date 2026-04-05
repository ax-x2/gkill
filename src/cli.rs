pub struct Config {
    pub query: String,
    pub force: bool,
    pub kill_all: bool,
    pub signal: Signal,
    pub use_regex: bool,
}

#[derive(Clone, Copy)]
pub enum Signal {
    Term,
    Kill,
}

impl Signal {
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
        }
    }
}

pub enum ParseOutcome {
    Help,
    Message(String),
}

pub fn parse_args<I>(args: I) -> Result<Config, ParseOutcome>
where
    I: IntoIterator<Item = String>,
{
    let mut force = false;
    let mut kill_all = false;
    let mut signal = Signal::Term;
    let mut use_regex = false;
    let mut query = None;

    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Err(ParseOutcome::Help),
            "--force" => force = true,
            "--all" => kill_all = true,
            "--regex" => use_regex = true,
            "--sigkill" | "-9" => signal = Signal::Kill,
            _ if arg.starts_with('-') => {
                return Err(ParseOutcome::Message(format!("unknown option: {arg}")));
            }
            _ if query.is_none() => query = Some(arg),
            _ => {
                return Err(ParseOutcome::Message(
                    "only one search pattern is supported".to_string(),
                ));
            }
        }
    }

    let query = query.ok_or_else(|| ParseOutcome::Message("missing search pattern".to_string()))?;
    if query.trim().is_empty() {
        return Err(ParseOutcome::Message(
            "search pattern must not be empty".to_string(),
        ));
    }

    Ok(Config {
        query,
        force,
        kill_all,
        signal,
        use_regex,
    })
}

pub fn print_usage() {
    eprintln!(
        "usage: gkill [--force] [--all] [--regex] [--sigkill|-9] <pattern>\n\
         \n\
         options:\n\
           --force      skip confirmation prompts\n\
           --all        target all matching processes\n\
           --regex      interpret <pattern> as a regex\n\
           --sigkill    send SIGKILL instead of SIGTERM\n\
           -9           alias for --sigkill\n\
           -h, --help   show this help"
    );
}
