//! Argumentos de línea de comandos y resolución del perfil.

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{ArgAction, Command, CommandFactory, FromArgMatches, Parser, ValueEnum};
use linaudit_core::i18n::{Lang, tr_dyn};
use linaudit_core::profile::{self, Detection};
use linaudit_core::{N_, Profile, ProfileSource, tr};

/// Ruta del archivo de configuración (se puede cambiar con LINAUDIT_CONFIG, útil en tests).
pub const DEFAULT_CONFIG: &str = "/etc/linaudit/config.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    Auto,
    Server,
    Desktop,
    Container,
}

impl ProfileArg {
    fn to_profile(self) -> Option<Profile> {
        match self {
            ProfileArg::Auto => None,
            ProfileArg::Server => Some(Profile::Server),
            ProfileArg::Desktop => Some(Profile::Desktop),
            ProfileArg::Container => Some(Profile::Container),
        }
    }
}

// Los textos de ayuda están en inglés (msgid) y se traducen en `command()`.
const ABOUT: &str = N_!("Read-only security audit for Linux.");
const LONG_ABOUT: &str = N_!(
    "Read-only security audit for Linux. It gives a score from 1 (worst) to 10 (best) and the list \
     of findings sorted by severity, with how to fix them.\n\n\
     Run it as root: without root several checks cannot read what they need."
);

#[derive(Debug, Parser)]
#[command(name = "linaudit", version, about = ABOUT, long_about = LONG_ABOUT, disable_help_flag = true, disable_version_flag = true)]
pub struct Args {
    #[arg(long, env = "LINAUDIT_PROFILE", value_enum, value_name = "PROFILE", help = N_!(
        "System profile. Without it, a menu is shown if there is a terminal; otherwise it is auto-detected."
    ))]
    pub profile: Option<ProfileArg>,

    #[arg(short = 'y', long, help = N_!("Do not show the profile menu even with a terminal (use auto-detection)."))]
    pub no_interactive: bool,

    #[arg(long, help = N_!("List the available profiles and exit."))]
    pub list_profiles: bool,

    #[arg(long, help = N_!("List the available categories and exit."))]
    pub list_categories: bool,

    #[arg(long, help = N_!("JSON output (for a central collector)."))]
    pub json: bool,

    #[arg(long, help = N_!("Text report instead of the interactive interface (TUI)."))]
    pub plain: bool,

    #[arg(long, help = N_!("Also include passed checks (in the TUI: start by showing all of them)."))]
    pub all: bool,

    #[arg(long, help = N_!("Skip the full filesystem sweeps (SUID, world-writable, etc.)."))]
    pub fast: bool,

    #[arg(long, value_delimiter = ',', value_name = "CATEGORIES", help = N_!("Run only these categories (e.g. ssh,accounts)."))]
    pub category: Vec<String>,

    #[arg(long, value_name = "FILE", help = N_!("Extra waivers file, besides /etc/linaudit/waivers.conf."))]
    pub waivers: Option<PathBuf>,

    #[arg(long = "rules-dir", alias = "rules", value_delimiter = ',', value_name = "DIR", help = N_!(
        "Directory or file with YAML compliance rules (SCA), besides /etc/linaudit/rules.d."
    ))]
    pub rules_dir: Vec<PathBuf>,

    #[arg(long, value_name = "FILE", help = N_!("Save the report to FILE (mode 600) instead of printing it."))]
    pub output: Option<PathBuf>,

    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=10), help = N_!(
        "Exit code 1 if the score is lower than N (useful in cron/CI)."
    ))]
    pub min_score: Option<u8>,

    #[arg(long, help = N_!("No colors (NO_COLOR is honored too)."))]
    pub no_color: bool,

    #[arg(long, env = "LINAUDIT_LANG", value_name = "LANG", value_parser = crate::lang::parse, help = N_!(
        "Interface language: es or en. By default, the one chosen on the welcome screen or the system locale."
    ))]
    pub lang: Option<Lang>,

    #[arg(long, value_name = "SHELL", hide = true, help = N_!("Generate shell completions (bash, zsh, fish...) and exit."))]
    pub completions: Option<clap_complete::Shell>,

    #[arg(short = 'h', long, action = ArgAction::Help, help = N_!("Show this help."))]
    pub help: Option<bool>,

    #[arg(short = 'V', long, action = ArgAction::Version, help = N_!("Show the version."))]
    pub version: Option<bool>,
}

/// Comando de clap con la ayuda en el idioma actual.
pub fn command() -> Command {
    let cmd = Args::command()
        .about(tr_dyn(ABOUT).to_string())
        .long_about(tr_dyn(LONG_ABOUT).to_string())
        .help_template(format!(
            "{{about-with-newline}}\n{}: {{usage}}\n\n{}:\n{{options}}{{after-help}}",
            tr!("Usage"),
            tr!("Options")
        ));
    let ids: Vec<clap::Id> = cmd.get_arguments().map(|a| a.get_id().clone()).collect();
    ids.into_iter().fold(cmd, |cmd, id| {
        cmd.mut_arg(id, |a| match a.get_help().map(ToString::to_string) {
            Some(h) => a.help(tr_dyn(&h).to_string()),
            None => a,
        })
    })
}

/// Argumentos ya parseados con la ayuda traducida. Sale (como clap) si hay un error o se pidió la ayuda.
pub fn parse() -> Args {
    let matches = command().get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

impl Args {
    /// Una persona está mirando: terminal en stdin y stdout, y nada en los argumentos
    /// que indique una corrida automatizada.
    pub fn tty_session(&self) -> bool {
        !self.json
            && self.output.is_none()
            && self.min_score.is_none()
            && std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
    }

    /// Mostrar el menú de perfil.
    pub fn interactive(&self) -> bool {
        !self.no_interactive && self.tty_session()
    }

    /// Mostrar la TUI en vez del reporte de texto.
    pub fn tui(&self) -> bool {
        !self.plain && self.tty_session()
    }
}

/// Lo que se decidió sin preguntar. `NeedsMenu` deja la elección al menú interactivo.
pub enum Resolved {
    Fixed(Profile, ProfileSource),
    NeedsMenu(Detection),
}

/// Configuración del sistema (LINAUDIT_CONFIG la reemplaza, útil en tests).
pub fn config_path() -> String {
    std::env::var("LINAUDIT_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string())
}

/// Prioridad: --profile / LINAUDIT_PROFILE > config.toml > menú (si hay terminal) > autodetección.
pub fn resolve_profile(args: &Args) -> Result<Resolved, String> {
    if let Some(p) = args.profile {
        return Ok(match p.to_profile() {
            Some(p) => Resolved::Fixed(p, ProfileSource::Argument),
            None => Resolved::Fixed(profile::detect().profile, ProfileSource::Auto),
        });
    }
    let config = config_path();
    match config_profile(&config)? {
        Some("auto") => return Ok(Resolved::Fixed(profile::detect().profile, ProfileSource::Auto)),
        Some(id) => {
            let p = Profile::from_id(id).ok_or_else(|| invalid_profile(&config, id))?;
            return Ok(Resolved::Fixed(p, ProfileSource::Config));
        }
        None => {}
    }
    let det = profile::detect();
    if args.interactive() {
        Ok(Resolved::NeedsMenu(det))
    } else {
        Ok(Resolved::Fixed(det.profile, ProfileSource::Auto))
    }
}

fn invalid_profile(path: &str, id: &str) -> String {
    tr!("{path}: invalid profile \"{id}\" (valid: auto, {valid})", path = path, id = id, valid = profile_ids())
}

pub fn profile_ids() -> String {
    Profile::ALL.iter().map(|p| p.id()).collect::<Vec<_>>().join(", ")
}

#[derive(serde::Deserialize)]
struct ConfigFile {
    profile: Option<String>,
}

/// Lee `profile = "..."` de config.toml. Si el archivo no existe no es un error; si está mal escrito, sí.
fn config_profile(path: &str) -> Result<Option<&'static str>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{path}: {e}")),
    };
    let cfg: ConfigFile = toml::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    Ok(match cfg.profile.as_deref() {
        None => None,
        Some("auto") => Some("auto"),
        Some(id) => match Profile::from_id(id) {
            Some(p) => Some(p.id()),
            None => return Err(invalid_profile(path, id)),
        },
    })
}
