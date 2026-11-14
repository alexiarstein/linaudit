//! Modelo de resultados: severidad, estado y el resultado de un control.

use serde::{Deserialize, Serialize};

/// Gravedad de un control. El orden de las variantes es el de mayor a menor gravedad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    #[serde(alias = "critical", alias = "Critical")]
    Critical,
    #[serde(alias = "high", alias = "High")]
    High,
    #[serde(alias = "medium", alias = "Medium")]
    Medium,
    #[serde(alias = "low", alias = "Low")]
    Low,
    #[serde(alias = "info", alias = "Info")]
    Info,
}

impl Severity {
    /// Peso en el puntaje. Ver `score.rs`.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Critical => 10.0,
            Severity::High => 6.0,
            Severity::Medium => 3.0,
            Severity::Low => 1.0,
            Severity::Info => 0.0,
        }
    }

    /// Nombre traducido, en mayúsculas.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => crate::trc!("severity", "CRITICAL"),
            Severity::High => crate::trc!("severity", "HIGH"),
            Severity::Medium => crate::trc!("severity", "MEDIUM"),
            Severity::Low => crate::trc!("severity", "LOW"),
            Severity::Info => crate::trc!("severity", "INFO"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Fail,
    Warn,
    /// No aplica a este sistema (no cuenta en el puntaje).
    Na,
    /// No se pudo evaluar (resta cobertura, ver `score.rs`).
    Error,
    /// Excepción documentada en waivers.conf (no cuenta en el puntaje, pero se muestra).
    Waived,
}

impl Status {
    /// Cuenta para el puntaje (PASS, FAIL o WARN).
    pub fn is_scored(self) -> bool {
        matches!(self, Status::Pass | Status::Fail | Status::Warn)
    }

    /// Hallazgo abierto que hay que mostrar (FAIL o WARN).
    pub fn is_open(self) -> bool {
        matches!(self, Status::Fail | Status::Warn)
    }
}

/// Largo máximo del detalle, como en la versión bash.
const MAX_DETAIL_CHARS: usize = 400;

/// Resultado de un control. Los campos de texto se sanean al construirlo:
/// pueden venir de archivos del sistema auditado y no deben poder inyectar
/// secuencias de escape en la terminal de quien lee el reporte.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckResult {
    pub id: String,
    pub severity: Severity,
    pub status: Status,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

impl CheckResult {
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        status: Status,
        category: impl Into<String>,
        title: impl AsRef<str>,
    ) -> Self {
        CheckResult {
            id: id.into(),
            severity,
            status,
            category: category.into(),
            title: sanitize(title.as_ref()),
            detail: String::new(),
            fix: String::new(),
        }
    }

    pub fn detail(mut self, detail: impl AsRef<str>) -> Self {
        self.set_detail(detail.as_ref());
        self
    }

    pub fn fix(mut self, fix: impl AsRef<str>) -> Self {
        self.fix = sanitize(fix.as_ref());
        self
    }

    pub fn set_detail(&mut self, detail: &str) {
        self.detail = sanitize(detail).chars().take(MAX_DETAIL_CHARS).collect();
    }
}

/// Reemplaza caracteres de control (incluido ESC) por espacios.
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// Acumulador que usan los controles, con atajos equivalentes a r_pass/r_fail/... de bash.
#[derive(Debug)]
pub struct Emitter {
    category: &'static str,
    results: Vec<CheckResult>,
}

impl Emitter {
    pub fn new(category: &'static str) -> Self {
        Emitter { category, results: Vec::new() }
    }

    pub fn category(&self) -> &'static str {
        self.category
    }

    /// Agrega un resultado y devuelve una referencia para completar detalle/arreglo.
    pub fn emit(&mut self, id: &str, sev: Severity, status: Status, title: &str) -> &mut CheckResult {
        self.results.push(CheckResult::new(id, sev, status, self.category, title));
        self.results.last_mut().expect("recién agregado")
    }

    pub fn pass(&mut self, id: &str, sev: Severity, title: &str) -> &mut CheckResult {
        self.emit(id, sev, Status::Pass, title)
    }
    pub fn fail(&mut self, id: &str, sev: Severity, title: &str) -> &mut CheckResult {
        self.emit(id, sev, Status::Fail, title)
    }
    pub fn warn(&mut self, id: &str, sev: Severity, title: &str) -> &mut CheckResult {
        self.emit(id, sev, Status::Warn, title)
    }
    pub fn na(&mut self, id: &str, sev: Severity, title: &str) -> &mut CheckResult {
        self.emit(id, sev, Status::Na, title)
    }
    pub fn error(&mut self, id: &str, sev: Severity, title: &str) -> &mut CheckResult {
        self.emit(id, sev, Status::Error, title)
    }

    pub fn into_results(self) -> Vec<CheckResult> {
        self.results
    }
}

/// Permite encadenar `.with_detail(..).with_fix(..)` sobre el `&mut` que devuelve el emisor.
pub trait ResultExt {
    fn with_detail(&mut self, d: impl AsRef<str>) -> &mut Self;
    fn with_fix(&mut self, f: impl AsRef<str>) -> &mut Self;
}

impl ResultExt for CheckResult {
    fn with_detail(&mut self, d: impl AsRef<str>) -> &mut Self {
        self.set_detail(d.as_ref());
        self
    }
    fn with_fix(&mut self, f: impl AsRef<str>) -> &mut Self {
        self.fix = sanitize(f.as_ref());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanea_secuencias_de_escape() {
        let r = CheckResult::new("X-1", Severity::Low, Status::Fail, "t", "a\x1b[31mb")
            .detail("línea1\nlínea2\x07");
        assert_eq!(r.title, "a [31mb");
        assert_eq!(r.detail, "línea1 línea2 ");
    }

    #[test]
    fn trunca_detalle_por_caracteres_no_bytes() {
        let r = CheckResult::new("X-1", Severity::Low, Status::Fail, "t", "t").detail("ñ".repeat(500));
        assert_eq!(r.detail.chars().count(), 400);
    }
}
