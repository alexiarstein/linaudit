//! linaudit-core: motor de la auditoría, sin nada de interfaz.
//! La CLI (texto/JSON) y la TUI consumen [`Report`].

pub mod checks;
pub mod i18n;
pub mod model;
pub mod profile;
pub mod sca;
pub mod score;
pub mod system;
pub mod waivers;

use serde::Serialize;

pub use checks::{Context, Module};
pub use model::{CheckResult, Severity, Status};
pub use profile::Profile;
pub use score::Score;
pub use system::OsInfo;
pub use waivers::Waivers;

/// Versión del formato JSON. Subirla solo con cambios incompatibles.
pub const JSON_SCHEMA: u32 = 1;

/// De dónde salió el perfil usado (queda en el reporte para distinguir elegido vs. adivinado).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileSource {
    /// --profile o LINAUDIT_PROFILE
    Argument,
    /// /etc/linaudit/config.toml
    Config,
    /// Elegido en el menú interactivo
    Menu,
    /// Autodetectado
    Auto,
}

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub profile: Profile,
    pub profile_source: ProfileSource,
    /// Categorías a correr; vacío = todas.
    pub categories: Vec<String>,
    pub fast: bool,
    pub waivers: Waivers,
    pub rules_dirs: Vec<std::path::PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: u32,
    pub tool: &'static str,
    pub version: &'static str,
    pub host: String,
    pub os: String,
    pub timestamp: String,
    pub root: bool,
    pub profile: Profile,
    pub profile_source: ProfileSource,
    /// Categorías pedidas con --category (vacío = auditoría completa).
    pub partial_categories: Vec<String>,
    #[serde(flatten)]
    pub score: Score,
    pub results: Vec<CheckResult>,
}

/// Corre la auditoría completa: controles -> ajustes de perfil -> excepciones -> puntaje.
/// `on_module` se llama antes de cada módulo (para mostrar progreso).
pub fn audit(opts: &AuditOptions, timestamp: String, on_module: impl FnMut(&Module)) -> Report {
    let os = OsInfo::detect();
    let root = system::is_root();
    let mut ctx = Context::new(os.clone(), root, opts.fast);
    ctx.rules_dirs = opts.rules_dirs.clone();
    let mut results = checks::run_all(&ctx, &opts.categories, on_module);
    profile::apply(opts.profile, &mut results);
    opts.waivers.apply(&mut results);
    let score = score::compute(&results);
    Report {
        schema: JSON_SCHEMA,
        tool: "linaudit",
        version: env!("CARGO_PKG_VERSION"),
        host: system::hostname(),
        os: os.pretty,
        timestamp,
        root,
        profile: opts.profile,
        profile_source: opts.profile_source,
        partial_categories: opts.categories.clone(),
        score,
        results,
    }
}
