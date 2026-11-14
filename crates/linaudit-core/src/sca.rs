//! Motor SCA (Security Configuration Assessment) compatible con el formato YAML
//! utilizado en Atomicorp / AWP Agent / Wazuh.
//!
//! Soporta políticas en YAML con reglas:
//!   - `c:<comando> -> r:<regex>`
//!   - `not c:<comando> -> r:<regex>`
//!   - `f:<archivo> -> r:<regex>`
//!   - `not f:<archivo> -> r:<regex>`
//!   - `d:<directorio> -> <extensiones> -> r:<regex>`
//!   - `d:<directorio> -> r:<regex>`
//!   - `not d:<directorio> -> ...`
//! Y condiciones: `all`, `any`, `none`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use regex::Regex;
use serde::{Deserialize, Deserializer};

use crate::checks::Context;
use crate::model::{Emitter, ResultExt, Severity};

/// Metadatos de la política.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyMeta {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub regex_type: Option<String>,
}

/// Identificador de control: puede ser un entero o un string en YAML.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CheckId {
    Int(u64),
    Str(String),
}

impl CheckId {
    pub fn as_str(&self) -> String {
        match self {
            CheckId::Int(n) => n.to_string(),
            CheckId::Str(s) => s.clone(),
        }
    }
}

impl<'de> Deserialize<'de> for CheckId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper {
            Int(u64),
            Str(String),
        }
        match Helper::deserialize(deserializer)? {
            Helper::Int(n) => Ok(CheckId::Int(n)),
            Helper::Str(s) => Ok(CheckId::Str(s)),
        }
    }
}

/// Un control individual dentro de una política YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct ScaCheck {
    pub id: CheckId,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub compliance: Option<serde_yaml::Value>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
}

/// Una política completa cargada desde un archivo YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub policy: PolicyMeta,
    #[serde(default)]
    pub variables: Option<HashMap<String, String>>,
    #[serde(default)]
    pub checks: Vec<ScaCheck>,
}

#[derive(Debug, Clone)]
pub enum RuleTarget {
    Command(String),
    File(PathBuf),
    Directory { path: PathBuf, extensions: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub target: RuleTarget,
    pub regex: Regex,
    pub pattern: String,
    pub negate: bool,
}

impl ParsedRule {
    /// Parsea una regla de texto con formato `target -> [exts ->] r:regex`
    pub fn parse(rule_text: &str, variables: Option<&HashMap<String, String>>) -> Result<Self, String> {
        let trimmed = rule_text.trim();
        let (negate, body) = if let Some(rest) = trimmed.strip_prefix("not ") {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        let parts: Vec<&str> = body.split("->").map(|s| s.trim()).collect();
        if parts.len() < 2 {
            return Err(format!("Regla sin separador '->': {rule_text}"));
        }

        let first = parts[0];
        let last = parts[parts.len() - 1];

        // Extraer regex del último componente `r:<patrón>`
        let pattern = if let Some(pat) = last.strip_prefix("r:") {
            pat.trim()
        } else {
            return Err(format!("Último componente de regla debe comenzar con 'r:': {last}"));
        };

        let regex = regex::RegexBuilder::new(pattern)
            .multi_line(true)
            .build()
            .map_err(|e| format!("Regex inválida '{pattern}': {e}"))?;

        if let Some(cmd) = first.strip_prefix("c:") {
            let cmd_str = resolve_vars(cmd.trim(), variables);
            Ok(ParsedRule {
                target: RuleTarget::Command(cmd_str),
                regex,
                pattern: pattern.to_string(),
                negate,
            })
        } else if let Some(file) = first.strip_prefix("f:") {
            let file_str = resolve_vars(file.trim(), variables);
            Ok(ParsedRule {
                target: RuleTarget::File(PathBuf::from(file_str)),
                regex,
                pattern: pattern.to_string(),
                negate,
            })
        } else if let Some(dir) = first.strip_prefix("d:") {
            let dir_str = resolve_vars(dir.trim(), variables);
            let extensions = if parts.len() >= 3 {
                parts[1]
                    .split('|')
                    .map(|ext| ext.trim().trim_end_matches('$').to_string())
                    .filter(|ext| !ext.is_empty())
                    .collect()
            } else {
                vec!["*".to_string()]
            };
            Ok(ParsedRule {
                target: RuleTarget::Directory {
                    path: PathBuf::from(dir_str),
                    extensions,
                },
                regex,
                pattern: pattern.to_string(),
                negate,
            })
        } else {
            Err(format!("Prefijo de regla desconocido (esperado c:, f: o d:): {first}"))
        }
    }
}

fn resolve_vars(input: &str, variables: Option<&HashMap<String, String>>) -> String {
    let Some(vars) = variables else { return input.to_string() };
    let mut out = input.to_string();
    for (k, v) in vars {
        let key_with_dollar = if k.starts_with('$') { k.clone() } else { format!("${k}") };
        out = out.replace(&key_with_dollar, v);
    }
    out
}

/// Estado compartido para optimizar ejecuciones repetidas de comandos.
#[derive(Default)]
pub struct CommandCache {
    cache: Mutex<HashMap<String, String>>,
}

impl CommandCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_run(&self, cmd: &str) -> String {
        let mut lock = self.cache.lock().unwrap();
        if let Some(out) = lock.get(cmd) {
            return out.clone();
        }
        let out = run_command(cmd);
        lock.insert(cmd.to_string(), out.clone());
        out
    }
}

fn run_command(cmd: &str) -> String {
    let child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();
    match child {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).to_string();
            if !out.stderr.is_empty() {
                if !s.is_empty() && !s.ends_with('\n') {
                    s.push('\n');
                }
                s.push_str(&String::from_utf8_lossy(&out.stderr));
            }
            s
        }
        Err(e) => format!("ERROR: {e}"),
    }
}

/// Evalúa una regla parsed contra el entorno del Contexto.
pub fn evaluate_rule(
    rule: &ParsedRule,
    ctx: &Context,
    cmd_cache: &CommandCache,
    matched_files: &mut Vec<String>,
) -> bool {
    let raw_match = match &rule.target {
        RuleTarget::Command(cmd) => {
            if !ctx.is_live() {
                // En modo fixture / test no corremos comandos arbitrarios del host
                false
            } else {
                let output = cmd_cache.get_or_run(cmd);
                rule.regex.is_match(&output)
            }
        }
        RuleTarget::File(rel_path) => {
            let path_str = rel_path.to_str().unwrap_or("");
            let real = ctx.path(path_str);
            if let Ok(content) = fs::read_to_string(&real) {
                let m = rule.regex.is_match(&content);
                if m {
                    matched_files.push(path_str.to_string());
                }
                m
            } else {
                false
            }
        }
        RuleTarget::Directory { path, extensions } => {
            let path_str = path.to_str().unwrap_or("");
            let real = ctx.path(path_str);
            let mut any_file_matched = false;

            if real.is_dir() {
                let walker = walkdir_simple(&real);
                for file_path in walker {
                    if let Some(name) = file_path.file_name().and_then(|n| n.to_str()) {
                        let allowed = extensions.iter().any(|ext| {
                            if ext == "*" {
                                true
                            } else if ext.starts_with('.') {
                                name.ends_with(ext)
                            } else {
                                name.contains(ext)
                            }
                        });
                        if allowed {
                            if let Ok(content) = fs::read_to_string(&file_path) {
                                if rule.regex.is_match(&content) {
                                    any_file_matched = true;
                                    if let Ok(disp) = file_path.strip_prefix(&ctx.fs_root) {
                                        matched_files.push(format!("/{}", disp.display()));
                                    } else {
                                        matched_files.push(file_path.display().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            any_file_matched
        }
    };

    if rule.negate {
        !raw_match
    } else {
        raw_match
    }
}

fn walkdir_simple(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                files.extend(walkdir_simple(&p));
            } else if p.is_file() {
                files.push(p);
            }
        }
    }
    files
}

/// Evalúa un ScaCheck completo.
pub fn evaluate_check(
    check: &ScaCheck,
    variables: Option<&HashMap<String, String>>,
    ctx: &Context,
    cmd_cache: &CommandCache,
) -> (bool, Vec<String>) {
    let mut matched_files = Vec::new();
    let mut rule_outcomes = Vec::new();

    for rule_str in &check.rules {
        match ParsedRule::parse(rule_str, variables) {
            Ok(rule) => {
                let outcome = evaluate_rule(&rule, ctx, cmd_cache, &mut matched_files);
                rule_outcomes.push(outcome);
            }
            Err(_e) => {
                rule_outcomes.push(false);
            }
        }
    }

    if rule_outcomes.is_empty() {
        return (true, matched_files);
    }

    let cond = check.condition.as_deref().unwrap_or("all").to_lowercase();
    let passed = match cond.as_str() {
        "all" => rule_outcomes.iter().all(|&r| r),
        "any" => rule_outcomes.iter().any(|&r| r),
        "none" => rule_outcomes.iter().all(|&r| !r),
        _ => rule_outcomes.iter().all(|&r| r),
    };

    (passed, matched_files)
}

/// Ejecuta todas las comprobaciones de una política y las emite mediante `Emitter`.
pub fn run_policy(policy: &Policy, ctx: &Context, em: &mut Emitter) {
    let cmd_cache = CommandCache::new();

    for check in &policy.checks {
        let (passed, matched_files) = evaluate_check(check, policy.variables.as_ref(), ctx, &cmd_cache);
        let check_id = format!("SCA-{}", check.id.as_str());
        let severity = check.severity.unwrap_or(Severity::Medium);

        let mut detail = check.rationale.clone().unwrap_or_else(|| check.description.clone().unwrap_or_default());
        if !matched_files.is_empty() {
            if !detail.is_empty() {
                detail.push('\n');
            }
            detail.push_str(&format!("Archivos detectados: {}", matched_files.join(", ")));
        }

        if passed {
            em.pass(&check_id, severity, &check.title);
        } else {
            let mut fail_res = em.fail(&check_id, severity, &check.title);
            if !detail.is_empty() {
                fail_res = fail_res.with_detail(detail);
            }
            if let Some(fix) = &check.remediation {
                fail_res = fail_res.with_fix(fix.clone());
            }
        }
    }
}

/// Normaliza cadenas YAML antes de pasarlas a serde_yaml, permitiendo secuencias de escape
/// de expresiones regulares como `\s`, `\d`, `\w`, `\b`, `\.`, etc. dentro de cadenas con comillas dobles,
/// tal como las admiten los analizadores de Wazuh y AWP.
pub fn sanitize_yaml_escapes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_double_quote = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '"' {
            in_double_quote = !in_double_quote;
            out.push(c);
        } else if in_double_quote && c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    // Escapes estándar de YAML a preservar tal cual
                    '\\' | '"' | 'n' | 'r' | 't' | '0' | 'a' | 'v' | 'f' | 'e' | ' ' | '\n' => {
                        out.push('\\');
                        out.push(next);
                        chars.next();
                    }
                    '\r' => {
                        out.push('\\');
                        out.push(next);
                        chars.next();
                        if chars.peek() == Some(&'\n') {
                            out.push('\n');
                            chars.next();
                        }
                    }
                    // Cualquier otro carácter (por ejemplo \s, \d, \w, \b, \., \+, \*, \?, etc.):
                    // Se escapa la barra invertida para que serde_yaml lo lea como barra literal.
                    _ => {
                        out.push('\\');
                        out.push('\\');
                    }
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Carga una política desde una cadena de texto YAML.
pub fn load_policy_str(yaml_str: &str) -> Result<Policy, String> {
    let sanitized = sanitize_yaml_escapes(yaml_str);
    serde_yaml::from_str(&sanitized).map_err(|e| e.to_string())
}

/// Carga un archivo de política YAML.
pub fn load_policy_file(path: &Path) -> Result<Policy, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("No se pudo leer {}: {e}", path.display()))?;
    load_policy_str(&content).map_err(|e| format!("Error de YAML en {}: {e}", path.display()))
}

/// Carga y ejecuta todas las políticas `.yml` y `.yaml` de un directorio (recursivo).
pub fn run_policies_from_dir(dir: &Path, ctx: &Context, em: &mut Emitter) -> usize {
    let mut count = 0;
    if !dir.is_dir() {
        return 0;
    }
    let mut files = walkdir_simple(dir);
    files.sort();
    for path in files {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            if ext == "yml" || ext == "yaml" {
                if let Ok(content) = fs::read_to_string(&path) {
                    if !content.contains("policy:") {
                        continue;
                    }
                }
                match load_policy_file(&path) {
                    Ok(policy) => {
                        run_policy(&policy, ctx, em);
                        count += 1;
                    }
                    Err(e) => {
                        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("rules.yml");
                        let id = format!("SCA-PARSE-{}", filename.replace('.', "-"));
                        em.error(&id, Severity::Low, &format!("Error al cargar {}", path.display()))
                            .with_detail(e);
                    }
                }
            }
        }
    }
    count
}

/// Ejecuta las políticas SCA encontradas en las rutas configuradas.
pub fn run(ctx: &Context, em: &mut Emitter) {
    let mut scanned_paths = Vec::new();

    // Directorio estándar del sistema: /etc/linaudit/rules.d
    let default_dir = ctx.path("/etc/linaudit/rules.d");
    if default_dir.is_dir() {
        scanned_paths.push(default_dir);
    }

    // Rutas adicionales provistas en el contexto (--rules-dir)
    for p in &ctx.rules_dirs {
        scanned_paths.push(p.clone());
    }

    let mut seen_files = std::collections::HashSet::new();

    for path in scanned_paths {
        if path.is_dir() {
            let mut files = walkdir_simple(&path);
            files.sort();
            for file in files {
                if let Some(ext) = file.extension().and_then(|s| s.to_str()) {
                    if ext == "yml" || ext == "yaml" {
                        if let Ok(content) = fs::read_to_string(&file) {
                            if !content.contains("policy:") {
                                continue;
                            }
                        }
                        let canonical = file.canonicalize().unwrap_or_else(|_| file.clone());
                        if seen_files.insert(canonical) {
                            match load_policy_file(&file) {
                                Ok(policy) => run_policy(&policy, ctx, em),
                                Err(e) => {
                                    let filename = file.file_name().and_then(|s| s.to_str()).unwrap_or("rules.yml");
                                    let id = format!("SCA-PARSE-{}", filename.replace('.', "-"));
                                    em.error(&id, Severity::Low, &format!("Error al cargar {}", file.display()))
                                        .with_detail(e);
                                }
                            }
                        }
                    }
                }
            }
        } else if path.is_file() {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
            if seen_files.insert(canonical) {
                match load_policy_file(&path) {
                    Ok(policy) => run_policy(&policy, ctx, em),
                    Err(e) => {
                        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("rules.yml");
                        let id = format!("SCA-PARSE-{}", filename.replace('.', "-"));
                        em.error(&id, Severity::Low, &format!("Error al cargar {}", path.display()))
                            .with_detail(e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use std::path::PathBuf;

    #[test]
    fn test_parse_rules() {
        let r1 = ParsedRule::parse("c:systemctl is-enabled cups -> r:disabled|not-found", None).unwrap();
        assert!(!r1.negate);
        assert_eq!(r1.pattern, "disabled|not-found");
        match r1.target {
            RuleTarget::Command(cmd) => assert_eq!(cmd, "systemctl is-enabled cups"),
            _ => panic!("Expected command target"),
        }

        let r2 = ParsedRule::parse("not c:systemctl status cups -> r:Active: active", None).unwrap();
        assert!(r2.negate);

        let r3 = ParsedRule::parse("d:/etc/modprobe.d/ -> .conf -> r:^blacklist\\s+cramfs", None).unwrap();
        assert!(!r3.negate);
        match r3.target {
            RuleTarget::Directory { path, extensions } => {
                assert_eq!(path, PathBuf::from("/etc/modprobe.d/"));
                assert_eq!(extensions, vec![".conf"]);
            }
            _ => panic!("Expected directory target"),
        }
    }

    #[test]
    fn test_file_rule_evaluation() {
        let fix = Fixture::new();
        fix.file("/etc/test.env", "GITHUB_TOKEN=ghp_123456789012345678901234567890123456\n");
        let ctx = fix.ctx();

        let yaml = r#"
policy:
  id: "test-token"
  name: "Token Check"

checks:
  - id: 4001
    title: "No tokens"
    condition: none
    rules:
      - "d:/etc/ -> .env -> r:^GITHUB_TOKEN=ghp_[A-Za-z0-9]{36}$"
"#;
        let policy: Policy = serde_yaml::from_str(yaml).unwrap();
        let cmd_cache = CommandCache::new();
        let (passed, matched_files) = evaluate_check(&policy.checks[0], None, &ctx, &cmd_cache);
        // Debe fallar porque encontró el token y la condición era "none"
        assert!(!passed);
        assert_eq!(matched_files.len(), 1);
    }

    #[test]
    fn test_awp_real_yaml_files() {
        let path = Path::new("/home/sshinn/src/awp-agent/src/awp-agent/compliance-scanner/tests/services/cups_check.yml");
        if path.exists() {
            let policy = load_policy_file(path).unwrap();
            assert_eq!(policy.policy.id, "test-cups");
            assert_eq!(policy.checks.len(), 1);
            assert_eq!(policy.checks[0].id, CheckId::Int(2001));
            assert_eq!(policy.checks[0].rules.len(), 2);
        }

        let path2 = Path::new("/home/sshinn/src/awp-agent/src/awp-agent/compliance-scanner/tests/kernel/modprobe_check.yml");
        if path2.exists() {
            let policy2 = load_policy_file(path2).unwrap();
            assert_eq!(policy2.policy.id, "test-modprobe");
            assert_eq!(policy2.checks.len(), 1);
            assert_eq!(policy2.checks[0].id, CheckId::Int(3022));
            assert_eq!(policy2.checks[0].rules.len(), 3);
        }

        let path3 = Path::new("/home/sshinn/src/awp-agent/src/awp-agent/compliance-scanner/tests/credentials/github_tokens.yml");
        if path3.exists() {
            let policy3 = load_policy_file(path3).unwrap();
            assert_eq!(policy3.policy.id, "test-github-tokens");
            assert_eq!(policy3.checks.len(), 1);
            assert_eq!(policy3.checks[0].id, CheckId::Int(4001));
            assert_eq!(policy3.checks[0].rules.len(), 4);
        }
    }
}
