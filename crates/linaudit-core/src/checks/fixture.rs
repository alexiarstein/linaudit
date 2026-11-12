//! Sistema de archivos falso para testear módulos sin tocar el sistema real.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::Context;
use crate::model::{CheckResult, Emitter};
use crate::system::OsInfo;

pub struct Fixture {
    root: PathBuf,
    services: HashSet<String>,
    pub is_root: bool,
    pub os: OsInfo,
    /// Modo --fast (por defecto sí: los fixtures no necesitan barridos completos).
    pub fast: bool,
}

impl Fixture {
    pub fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "linaudit-fixture-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Fixture { root, services: HashSet::new(), is_root: true, os: OsInfo::parse("ID=debian\nVERSION_ID=13\n"), fast: true }
    }

    /// Crea `abs` (ruta absoluta del sistema simulado) con este contenido.
    pub fn file(&self, abs: &str, content: &str) -> &Self {
        let p = self.root.join(abs.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
        self
    }

    pub fn mode(&self, abs: &str, mode: u32) -> &Self {
        let p = self.root.join(abs.trim_start_matches('/'));
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        self
    }

    pub fn dir(&self, abs: &str) -> &Self {
        std::fs::create_dir_all(self.root.join(abs.trim_start_matches('/'))).unwrap();
        self
    }

    /// Crea `abs` como un symlink a `target` (tal cual, relativo o absoluto): sirve para
    /// modelar los drop-in `*-enabled` de Apache/nginx.
    pub fn symlink(&self, abs: &str, target: &str) -> &Self {
        let p = self.root.join(abs.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(target, &p).unwrap();
        self
    }

    pub fn service(&mut self, name: &str) -> &mut Self {
        self.services.insert(name.to_string());
        self
    }

    pub fn ctx(&self) -> Context {
        Context {
            os: self.os.clone(),
            root: self.is_root,
            fast: self.fast,
            fs_root: self.root.clone(),
            active_services: Some(self.services.clone()),
            // 2026-11-04 12:00 UTC
            now_unix: 1_793_793_600,
        }
    }

    /// Corre un módulo y devuelve los resultados indexados por ID.
    pub fn run(&self, f: fn(&Context, &mut Emitter)) -> HashMap<String, CheckResult> {
        let mut em = Emitter::new("test");
        f(&self.ctx(), &mut em);
        em.into_results().into_iter().map(|r| (r.id.clone(), r)).collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
