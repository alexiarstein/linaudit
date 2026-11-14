//! linaudit — auditoría de seguridad de solo lectura para Linux.
//!
//! Códigos de salida: 0 ok · 1 puntaje menor a --min-score (o sin datos) · 2 error de uso · 130 cancelado.

mod cli;
mod lang;
mod menu;
mod text;
mod tui;

use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::ExitCode;

use cli::{Args, Resolved};
use linaudit_core::{AuditOptions, Profile, ProfileSource, Waivers, checks, profile, system, tr};

fn main() -> ExitCode {
    // el idioma va antes que clap, para que la ayuda salga traducida
    let argv: Vec<String> = std::env::args().collect();
    let (lang, lang_source) = lang::resolve(&argv, std::path::Path::new(&cli::config_path()));
    linaudit_core::i18n::set_lang(lang);
    let args = cli::parse();
    match run(args, lang_source) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("linaudit: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Args, lang_source: lang::Source) -> Result<ExitCode, String> {
    if let Some(shell) = args.completions {
        clap_complete::generate(shell, &mut cli::command(), "linaudit", &mut std::io::stdout());
        return Ok(ExitCode::SUCCESS);
    }
    if args.list_profiles {
        list_profiles();
        return Ok(ExitCode::SUCCESS);
    }
    if args.list_categories {
        for m in checks::MODULES {
            println!("{:<14} {}", m.category, m.label());
        }
        return Ok(ExitCode::SUCCESS);
    }
    if std::env::consts::OS != "linux" {
        return Err(tr!("only Linux is supported").into());
    }
    let available = checks::categories();
    if let Some(bad) = args.category.iter().find(|c| !available.contains(&c.as_str())) {
        return Err(tr!("unknown category: {bad} (available: {available})", bad = bad, available = available.join(", ")));
    }

    install_panic_hook();

    let resolved = cli::resolve_profile(&args)?;
    // con la TUI, la elección del perfil la hace la pantalla de bienvenida; sin TUI, el menú en línea
    let (profile, profile_source, welcome) = match resolved {
        Resolved::Fixed(p, s) => (p, s, None),
        Resolved::NeedsMenu(det) if args.tui() => (det.profile, ProfileSource::Menu, Some(det)),
        Resolved::NeedsMenu(det) => {
            let header =
                format!("linaudit {} — {} ({})", env!("CARGO_PKG_VERSION"), system::hostname(), linaudit_core::OsInfo::detect().pretty);
            match menu::choose_profile(&det, &header).map_err(|e| tr!("menu: {e}", e = e))? {
                Some(p) => (p, ProfileSource::Menu, None),
                None => return Ok(ExitCode::from(130)),
            }
        }
    };

    let mut waiver_files = vec![std::path::PathBuf::from("/etc/linaudit/waivers.conf")];
    if let Some(w) = &args.waivers {
        if !w.is_file() {
            return Err(tr!("waivers file {path} does not exist", path = w.display()));
        }
        waiver_files.push(w.clone());
    }
    for r in &args.rules_dir {
        if !r.exists() {
            return Err(tr!("rules path {path} does not exist", path = r.display()));
        }
    }
    let opts = AuditOptions {
        profile,
        profile_source,
        categories: args.category.clone(),
        fast: args.fast,
        waivers: Waivers::load(&waiver_files),
        rules_dirs: args.rules_dir.clone(),
    };

    let now = jiff::Zoned::now();
    let timestamp = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

    if args.tui() {
        let start = tui::Start {
            opts,
            timestamp,
            start_all: args.all,
            color: tui::ColorMode::detect(args.no_color),
            detection: welcome.clone().unwrap_or_else(profile::detect),
            welcome: welcome.is_some(),
            // la primera vez (sin idioma elegido) la bienvenida empieza preguntando el idioma
            ask_language: welcome.is_some() && !lang_source.is_explicit(),
        };
        let report = tui::run(start).map_err(|e| tr!("interface: {e}", e = e))?;
        match report {
            Some(r) => print_summary(&r),
            None => println!("{}", tr!("linaudit: audit interrupted.")),
        }
        return Ok(ExitCode::SUCCESS);
    }
    let progress = std::io::stderr().is_terminal() && !args.json;
    let report = linaudit_core::audit(&opts, timestamp, |m| {
        if progress {
            eprint!("\r\x1b[2K  {}", tr!("analyzing {category}…", category = m.category));
        }
    });
    if progress {
        eprint!("\r\x1b[2K");
    }

    let to_terminal = args.output.is_none() && std::io::stdout().is_terminal();
    let rendered = if args.json {
        serde_json::to_string(&report).map_err(|e| e.to_string())? + "\n"
    } else {
        let color = to_terminal && !args.no_color && std::env::var_os("NO_COLOR").is_none();
        let user = system::effective_uid()
            .and_then(system::user_name)
            .unwrap_or_else(|| tr!("unknown").into());
        text::render(
            &report,
            &text::Style::detect(color),
            args.all,
            &user,
            &now.strftime("%Y-%m-%d %H:%M:%S %Z").to_string(),
        )
    };

    match &args.output {
        Some(path) => {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            // si el archivo ya existía con otros permisos, mode() no los cambia
            f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
            f.write_all(rendered.as_bytes()).map_err(|e| e.to_string())?;
            let sc = report.score.score.map_or(tr!("no data").into(), |s| format!("{s}/10"));
            eprintln!("{}", tr!("Report saved to {path} (score {score})", path = path.display(), score = sc));
        }
        None => {
            let mut out = std::io::stdout().lock();
            // un pipe cerrado (ej. `| head`) no es un error
            let _ = out.write_all(rendered.as_bytes());
        }
    }

    // sin datos no se puede certificar nada: con --min-score eso cuenta como incumplimiento
    if let Some(min) = args.min_score {
        match report.score.score {
            Some(s) if s >= min => {}
            _ => return Ok(ExitCode::from(1)),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Un módulo que entra en pánico ya queda registrado como ERROR en el reporte, así que su
/// mensaje solo se muestra con LINAUDIT_DEBUG=1. Cualquier otro pánico (un bug de la interfaz)
/// primero restaura la terminal, para no dejarla en modo raw.
fn install_panic_hook() {
    let debug = std::env::var("LINAUDIT_DEBUG").as_deref() == Ok("1");
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let in_module = std::thread::current().name() == Some(tui::AUDIT_THREAD)
            || std::thread::current().name() == Some("main") && !tui::ACTIVE.load(std::sync::atomic::Ordering::SeqCst);
        if in_module && !debug {
            return;
        }
        tui::restore_terminal();
        default(info);
    }));
}

/// Lo que queda en la terminal al salir de la TUI.
fn print_summary(r: &linaudit_core::Report) {
    let s = &r.score;
    let score = match s.score {
        Some(sc) if s.incomplete => tr!("{score}/10 (incomplete evaluation)", score = sc),
        Some(sc) => format!("{sc}/10 ({})", text::verdict(sc)),
        None => tr!("no data").into(),
    };
    println!(
        "{}",
        tr!(
            "linaudit: {score} · {fail} failing · {warn} warnings · profile {profile}",
            score = score,
            fail = s.counts.fail,
            warn = s.counts.warn,
            profile = r.profile.label()
        )
    );
    println!("  {}", tr!("text report: linaudit --plain --profile {profile}", profile = r.profile.id()));
}

fn list_profiles() {
    let det = profile::detect();
    for p in Profile::ALL {
        let mark = if p == det.profile { tr!("  (detected on this system)") } else { "" };
        println!("{:<10} {}{mark}", p.id(), p.label());
        println!("           {}", p.description());
    }
    println!("\nauto       {}", tr!("auto-detect: {reasons}", reasons = det.reasons.join(", ")));
}
