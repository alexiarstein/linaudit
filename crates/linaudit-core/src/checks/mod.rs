//! Registro de módulos de control y ejecución aislada.
//!
//! REGLA DE ORO: todo es de SOLO LECTURA. Ningún control puede modificar el sistema.

pub mod accounts;
pub mod apps;
pub mod filesystem;
pub mod hardening;
pub mod network;
pub mod patching;
pub mod persistence;
pub mod secrets;
pub mod ssh;
pub mod util;
pub mod walk;

#[cfg(test)]
pub(crate) mod fixture;

use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use crate::model::{CheckResult, Emitter, Severity, Status};
use crate::system::OsInfo;
use crate::tr;

/// Lo que un módulo sabe del entorno en el que corre.
#[derive(Debug, Clone)]
pub struct Context {
    pub os: OsInfo,
    pub root: bool,
    /// Saltear barridos completos de filesystem.
    pub fast: bool,
    /// Raíz del filesystem auditado. "/" en producción; un directorio de fixtures en tests.
    pub fs_root: PathBuf,
    /// Servicios activos fijos (tests). `None` = consultar systemd o /proc.
    pub active_services: Option<HashSet<String>>,
    /// Momento de la auditoría (segundos Unix). Fijo en tests para fechas reproducibles.
    pub now_unix: i64,
    /// Directorios o archivos adicionales con reglas SCA en formato YAML.
    pub rules_dirs: Vec<PathBuf>,
}

impl Context {
    pub fn new(os: OsInfo, root: bool, fast: bool) -> Self {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Context {
            os,
            root,
            fast,
            fs_root: PathBuf::from("/"),
            active_services: None,
            now_unix,
            rules_dirs: Vec::new(),
        }
    }

    pub fn with_rules_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.rules_dirs = dirs;
        self
    }

    /// Traduce una ruta absoluta del sistema auditado a la ruta real a leer.
    pub fn path(&self, abs: &str) -> PathBuf {
        self.fs_root.join(abs.trim_start_matches('/'))
    }

    /// true si se audita el sistema real (y entonces se pueden ejecutar comandos como `sshd -T`).
    pub fn is_live(&self) -> bool {
        self.fs_root == Path::new("/")
    }
}

/// Un módulo agrupa los controles de una categoría.
pub struct Module {
    pub category: &'static str,
    /// En inglés (msgid): para mostrarla, [`Module::label`].
    pub description: &'static str,
    pub run: fn(&Context, &mut Emitter),
}

impl Module {
    /// Descripción traducida.
    pub fn label(&self) -> &'static str {
        crate::i18n::tr(self.description)
    }
}

/// Módulos portados a Rust, en orden de ejecución.
/// Para sumar una categoría: crear el archivo, agregarlo acá y documentar sus IDs en docs/CHECKS.md.
pub static MODULES: &[Module] = &[
    Module { category: "accounts", description: crate::N_!("Accounts, passwords and sudo"), run: accounts::run },
    Module { category: "ssh", description: crate::N_!("Effective OpenSSH configuration"), run: ssh::run },
    Module {
        category: "filesystem",
        description: crate::N_!("Critical permissions, SUID/SGID, world-writable files and mounts"),
        run: filesystem::run,
    },
    Module {
        category: "secrets",
        description: crate::N_!("Plaintext credentials, private keys and histories"),
        run: secrets::run,
    },
    Module { category: "network", description: crate::N_!("Firewall, exposed ports and network parameters"), run: network::run },
    Module {
        category: "patching",
        description: crate::N_!("Updates, pending reboot, end of support and repositories"),
        run: patching::run,
    },
    Module {
        category: "persistence",
        description: crate::N_!("Indicators of compromise and persistence mechanisms"),
        run: persistence::run,
    },
    Module {
        category: "hardening",
        description: crate::N_!("MAC, auditing, time, logs, kernel parameters and services"),
        run: hardening::run,
    },
    Module { category: "apps", description: crate::N_!("Tomcat, Redis, Docker, PostgreSQL, Samba, Apache and nginx"), run: apps::run },
    Module {
        category: "sca",
        description: crate::N_!("Security Configuration Assessment (SCA YAML rules)"),
        run: crate::sca::run,
    },
];

pub fn categories() -> Vec<&'static str> {
    MODULES.iter().map(|m| m.category).collect()
}

/// Corre los módulos (todos, o solo las categorías en `only`). Cada módulo corre aislado:
/// si entra en pánico se conserva lo que emitió hasta ese punto y se agrega un ERROR,
/// como hacía el subshell en bash.
pub fn run_all(ctx: &Context, only: &[String], mut on_module: impl FnMut(&Module)) -> Vec<CheckResult> {
    let mut results = Vec::new();
    for m in MODULES {
        if !only.is_empty() && !only.iter().any(|c| c == m.category) {
            continue;
        }
        on_module(m);
        let mut em = Emitter::new(m.category);
        let outcome = catch_unwind(AssertUnwindSafe(|| (m.run)(ctx, &mut em)));
        results.extend(em.into_results());
        if outcome.is_err() {
            // Señal explícita de pánico de módulo: `module_panic()` la marca y
            // `score::compute` la consume para aplicar el techo de cobertura. No
            // dependemos del prefijo "RUN-" del id, que es solo para mostrar.
            results.push(
                CheckResult::new(
                    format!("RUN-{}", m.category),
                    Severity::Low,
                    Status::Error,
                    m.category,
                    tr!("The {category} module ended with an error", category = m.category),
                )
                .detail(tr!("run with LINAUDIT_DEBUG=1 to see the details"))
                .module_panic(),
            );
        }
    }
    results
}
