//! Utilidades compartidas por los controles (equivalentes a lib/common.sh).

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::Context;
use crate::model::{Emitter, ResultExt, Severity};
use crate::system::user_name;
use crate::tr;

/// Permisos (los 12 bits bajos) de un archivo. Sigue symlinks (a diferencia de `stat -c %a`
/// de bash, que reportaba los del link): lo que importa es quién puede leer el archivo real.
pub fn file_mode(p: &Path) -> Option<u32> {
    std::fs::metadata(p).ok().map(|m| m.mode() & 0o7777)
}

/// true si `mode` no tiene ningún permiso fuera de `max`.
pub fn mode_within(mode: u32, max: u32) -> bool {
    mode & !max & 0o7777 == 0
}

/// Archivos de `dir` cuyo nombre empieza con `prefix` y termina con `suffix`, ordenados (como un glob de bash).
pub fn glob(dir: &Path, prefix: &str, suffix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.len() >= prefix.len() + suffix.len() && n.starts_with(prefix) && n.ends_with(suffix)
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Ubica un ejecutable en el PATH o en los directorios sbin habituales
/// (cron y sudo no siempre tienen sbin en el PATH).
pub fn find_command(name: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .filter(|d| d.starts_with('/'))
        .chain(["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin"])
        .map(|d| Path::new(d).join(name))
        .find(|p| p.metadata().map(|m| m.is_file() && m.mode() & 0o111 != 0).unwrap_or(false))
}

/// Ejecuta un comando sin shell y devuelve su stdout si no está vacío. stderr se descarta.
pub fn command_output(cmd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).into_owned();
    (!s.trim().is_empty()).then_some(s)
}

/// Equivalente a `check_file_perm` de bash: N/A si no existe, ERROR si no se puede leer.
#[allow(clippy::too_many_arguments)]
pub fn check_file_perm(
    em: &mut Emitter,
    ctx: &Context,
    id: &str,
    sev: Severity,
    title: &str,
    file: &str,
    max: u32,
    owner_uid: Option<u32>,
) {
    let p = ctx.path(file);
    let meta = match std::fs::metadata(&p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            em.na(id, sev, title).with_detail(tr!("{file} does not exist", file = file));
            return;
        }
        Err(_) => {
            em.error(id, sev, title).with_detail(tr!("could not read {file}", file = file));
            return;
        }
    };
    let mode = meta.mode() & 0o7777;
    let mut problems = Vec::new();
    if !mode_within(mode, max) {
        problems.push(tr!("mode {mode} (expected at most {max})", mode = format!("{mode:o}"), max = format!("{max:o}")));
    }
    let owner_name = |uid: u32| user_name(uid).unwrap_or_else(|| uid.to_string());
    if let Some(want) = owner_uid {
        if meta.uid() != want {
            problems.push(tr!("owner {owner} (expected {expected})", owner = owner_name(meta.uid()), expected = owner_name(want)));
        }
    }
    if problems.is_empty() {
        em.pass(id, sev, title).with_detail(file);
    } else {
        let mut fix = format!("chmod {max:o} {file}");
        if let Some(want) = owner_uid {
            fix.push_str(&format!(" && chown {} {file}", owner_name(want)));
        }
        em.fail(id, sev, title).with_detail(format!("{file}: {}", problems.join(", "))).with_fix(fix);
    }
}

/// Lee un archivo del sistema auditado como texto.
pub fn read(ctx: &Context, abs: &str) -> Option<String> {
    std::fs::read_to_string(ctx.path(abs)).ok()
}

/// Resultado de leer una configuración relevante para la seguridad, distinguiendo
/// "ausente" de "presente pero ilegible". `read` colapsa ambos casos en `None`, lo que
/// permite que un archivo presente pero sin permiso de lectura se interprete como
/// "sin directiva insegura" y produzca un PASS falso en un control crítico.
pub enum ConfigRead {
    /// El archivo no existe.
    Absent,
    /// El archivo existe pero no se pudo leer (permiso o error de E/S).
    Unreadable,
    /// Contenido leído correctamente.
    Content(String),
}

/// Lee una configuración distinguiendo ausencia de "presente pero ilegible".
pub fn read_config(ctx: &Context, abs: &str) -> ConfigRead {
    match std::fs::read_to_string(ctx.path(abs)) {
        Ok(t) => ConfigRead::Content(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfigRead::Absent,
        Err(_) => ConfigRead::Unreadable,
    }
}

/// Un control cuya configuración está presente pero no se pudo leer queda
/// indeterminado: Error, nunca PASS. Conserva el título propio del control y
/// pone el motivo en el detalle, igual que ACC-002 ("cannot read ... (not root?)").
pub fn unreadable<S: AsRef<str>>(em: &mut Emitter, id: &str, sev: Severity, title: &str, files: &[S]) {
    let list = files.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ");
    em.error(id, sev, title)
        .with_detail(tr!("cannot read {files} (not root?)", files = list))
        .with_fix(tr!("Grant read access so the audit can evaluate this file"));
}

/// Valor de una clave en /etc/login.defs (gana la última aparición, como el awk de bash).
pub fn login_defs_get(ctx: &Context, key: &str) -> Option<String> {
    let text = read(ctx, "/etc/login.defs")?;
    let mut val = None;
    for line in text.lines() {
        let mut w = line.split_whitespace();
        if w.next() == Some(key) {
            val = Some(w.next().unwrap_or("").to_string());
        }
    }
    val.filter(|v| !v.is_empty())
}

/// Una línea de /etc/passwd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub password: String,
    /// `None` si el campo no es numérico.
    pub uid: Option<u32>,
    pub home: String,
    pub shell: String,
}

pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let get = |i: usize| f.get(i).copied().unwrap_or("").to_string();
            PasswdEntry {
                name: get(0),
                password: get(1),
                uid: f.get(2).and_then(|u| u.parse().ok()),
                home: get(5),
                shell: get(6),
            }
        })
        .collect()
}

/// (cuenta, hash) de /etc/shadow.
pub fn parse_shadow(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut f = l.split(':');
            (f.next().unwrap_or("").to_string(), f.next().unwrap_or("").to_string())
        })
        .collect()
}

/// Valor de un parámetro del kernel, leído de /proc/sys.
pub fn sysctl_get(ctx: &Context, key: &str) -> Option<String> {
    let v = read(ctx, &format!("/proc/sys/{}", key.replace('.', "/")))?;
    let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
    (!v.is_empty()).then_some(v)
}

/// Equivalente a `check_sysctl` de bash: PASS si el valor es uno de `ok`.
pub fn check_sysctl(em: &mut Emitter, ctx: &Context, id: &str, sev: Severity, title: &str, key: &str, ok: &[&str]) {
    let Some(v) = sysctl_get(ctx, key) else {
        em.na(id, sev, title).with_detail(tr!("{key} unavailable", key = key));
        return;
    };
    if ok.contains(&v.as_str()) {
        em.pass(id, sev, title).with_detail(format!("{key} = {v}"));
    } else {
        em.fail(id, sev, title)
            .with_detail(tr!("{key} = {v} (expected: {expected})", expected = ok.join(tr!(" or ")), key = key, v = v))
            .with_fix(tr!("sysctl -w {key}=<value> and persist it in /etc/sysctl.d/", key = key));
    }
}

/// Cuáles de estos servicios están activos. Con systemd hace una sola llamada a
/// `systemctl is-active` para todos; sin systemd (contenedores, SysV) busca el proceso por nombre.
pub fn active_services(ctx: &Context, names: &[&str]) -> HashSet<String> {
    if let Some(fixed) = &ctx.active_services {
        return names.iter().filter(|n| fixed.contains(**n)).map(|n| n.to_string()).collect();
    }
    if !ctx.is_live() {
        return HashSet::new();
    }
    if Path::new("/run/systemd/system").is_dir() {
        if let Some(systemctl) = find_command("systemctl") {
            let mut args = vec!["is-active", "--"];
            args.extend_from_slice(names);
            // is-active imprime un estado por unidad, en el mismo orden, aunque salga con error
            if let Ok(out) = Command::new(systemctl).args(&args).stdin(Stdio::null()).stderr(Stdio::null()).output() {
                let text = String::from_utf8_lossy(&out.stdout);
                let states: Vec<&str> = text.lines().collect();
                if states.len() == names.len() {
                    return names
                        .iter()
                        .zip(states)
                        .filter(|(_, st)| *st == "active")
                        .map(|(n, _)| n.to_string())
                        .collect();
                }
            }
        }
    }
    names
        .iter()
        .filter(|n| crate::profile::process_running(n.strip_suffix(".service").unwrap_or(n)))
        .map(|n| n.to_string())
        .collect()
}

/// Resultado completo de un comando: si salió bien, stdout y stderr.
pub struct CmdOutput {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Ejecuta un comando (sin shell) con variables de entorno extra, solo sobre el sistema real.
pub fn live_command_full(ctx: &Context, name: &str, args: &[&str], env: &[(&str, &str)]) -> Option<CmdOutput> {
    if !ctx.is_live() {
        return None;
    }
    let out = Command::new(find_command(name)?)
        .args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .ok()?;
    Some(CmdOutput {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// true si la unidad de systemd está habilitada.
pub fn unit_enabled(ctx: &Context, unit: &str) -> bool {
    if let Some(fixed) = &ctx.active_services {
        return fixed.contains(unit);
    }
    ctx.is_live()
        && Path::new("/run/systemd/system").is_dir()
        && live_command_full(ctx, "systemctl", &["is-enabled", "--quiet", unit], &[]).is_some_and(|o| o.ok)
}

/// Paquete instalado según dpkg (leyendo su base directamente) o rpm.
pub fn pkg_installed(ctx: &Context, name: &str) -> bool {
    use crate::system::OsFamily;
    match ctx.os.family {
        OsFamily::Debian => read(ctx, "/var/lib/dpkg/status").is_some_and(|t| dpkg_installed(&t, name)),
        OsFamily::Rhel => live_command_full(ctx, "rpm", &["-q", name], &[]).is_some_and(|o| o.ok),
        OsFamily::Unknown => false,
    }
}

/// Busca la estrofa `Package: name` con `Status: install ok installed` en /var/lib/dpkg/status.
pub fn dpkg_installed(status: &str, name: &str) -> bool {
    status.split("\n\n").any(|stanza| {
        let mut pkg = false;
        let mut installed = false;
        for l in stanza.lines() {
            if let Some(p) = l.strip_prefix("Package: ") {
                pkg = p.trim() == name;
            } else if let Some(st) = l.strip_prefix("Status: ") {
                installed = st.trim() == "install ok installed";
            }
        }
        pkg && installed
    })
}

/// Archivos de un directorio (no recursivo), ordenados. Equivalente a `dir/*` en bash.
pub fn dir_files(ctx: &Context, abs_dir: &str) -> Vec<(String, PathBuf)> {
    let mut v: Vec<(String, PathBuf)> = std::fs::read_dir(ctx.path(abs_dir))
        .map(|d| {
            d.flatten()
                .filter(|e| e.path().is_file())
                .map(|e| (format!("{}/{}", abs_dir.trim_end_matches('/'), e.file_name().to_string_lossy()), e.path()))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Fecha civil (AAAA-MM-DD, UTC) de un instante Unix. Algoritmo de Howard Hinnant.
pub fn civil_date(unix: i64) -> String {
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Resultado de un comando con límite de tiempo.
pub enum Timed {
    Done(CmdOutput),
    TimedOut,
}

/// Ejecuta un comando (sin shell) sobre el sistema real, matándolo si supera `limit`.
/// `None` si no se audita el sistema real o el comando no existe.
pub fn live_command_timeout(ctx: &Context, name: &str, args: &[&str], limit: std::time::Duration) -> Option<Timed> {
    use std::io::Read;
    if !ctx.is_live() {
        return None;
    }
    let mut child = Command::new(find_command(name)?)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    // leer en hilos para que un pipe lleno no bloquee al proceso
    let mut out = child.stdout.take()?;
    let mut err = child.stderr.take()?;
    let t_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = out.read_to_end(&mut v);
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = err.read_to_end(&mut v);
        v
    });
    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Some(Timed::TimedOut);
            }
        }
    };
    Some(Timed::Done(CmdOutput {
        ok: status.success(),
        stdout: String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned(),
        stderr: String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned(),
    }))
}

/// Archivos que coinciden con un glob simple de bash: `dir/prefijo*sufijo`, con un solo `*`
/// en el último componente y opcionalmente `*` como directorio intermedio (`/home/*/.bashrc`).
/// Devuelve rutas lógicas ordenadas, como la expansión de bash.
pub fn expand(ctx: &Context, pattern: &str) -> Vec<String> {
    let parts: Vec<&str> = pattern.trim_start_matches('/').split('/').collect();
    let mut acc = vec![String::new()];
    for (i, part) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        let mut next = Vec::new();
        for base in &acc {
            if part.contains('*') || part.contains('?') || part.contains('[') {
                let dir = if base.is_empty() { "/".to_string() } else { base.clone() };
                let mut names: Vec<String> = std::fs::read_dir(ctx.path(&dir))
                    .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
                    .unwrap_or_default();
                names.sort();
                for n in names {
                    // como bash: el comodín no matchea archivos ocultos salvo que el patrón empiece con "."
                    if n.starts_with('.') && !part.starts_with('.') {
                        continue;
                    }
                    if super::walk::glob_match(part, &n) {
                        next.push(format!("{base}/{n}"));
                    }
                }
            } else {
                next.push(format!("{base}/{part}"));
            }
        }
        acc = next;
        if !last {
            acc.retain(|p| ctx.path(p).is_dir());
        }
    }
    acc.retain(|p| ctx.path(p).exists());
    acc
}

/// Varias expansiones, en orden (como pasar varios globs a un comando).
pub fn expand_all(ctx: &Context, patterns: &[&str]) -> Vec<String> {
    patterns.iter().flat_map(|p| expand(ctx, p)).collect()
}

/// Líneas que coinciden con `re` en cada archivo, como `grep -Hn`: (archivo, n° de línea, línea).
/// `max_per_file` imita `-m`; los archivos binarios se saltean (como `-I`).
pub fn grep_files(
    ctx: &Context,
    files: &[String],
    re: &regex::Regex,
    max_per_file: Option<usize>,
) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for f in files {
        let Some(text) = super::walk::read_text(&ctx.path(f)) else { continue };
        let mut n = 0;
        for (i, line) in text.lines().enumerate() {
            if re.is_match(line) {
                out.push((f.clone(), i + 1, line.to_string()));
                n += 1;
                if max_per_file.is_some_and(|m| n >= m) {
                    break;
                }
            }
        }
    }
    out
}

/// Como `grep -Hn` sin `-I`: también lee archivos con bytes binarios. (archivo, n° de línea, línea).
pub fn grep_files_raw(ctx: &Context, files: &[String], re: &regex::Regex) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for f in files {
        let Ok(bytes) = std::fs::read(ctx.path(f)) else { continue };
        for (i, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
            if re.is_match(line) {
                out.push((f.clone(), i + 1, line.to_string()));
            }
        }
    }
    out
}

/// Ejecuta un comando del sistema solo si se audita el sistema real y el comando existe.
pub fn live_command(ctx: &Context, name: &str, args: &[&str]) -> Option<String> {
    if !ctx.is_live() {
        return None;
    }
    command_output(&find_command(name)?, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsea_passwd() {
        let p = parse_passwd("root:x:0:0:root:/root:/bin/bash\nraro:x:abc:1::/:\n\n");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].uid, Some(0));
        assert_eq!(p[0].shell, "/bin/bash");
        assert_eq!(p[1].uid, None);
        assert_eq!(p[1].shell, "");
    }

    #[test]
    fn fechas_civiles() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(951_782_400), "2000-02-29");
        assert_eq!(civil_date(1_793_793_600), "2026-11-04");
    }

    #[test]
    fn dpkg_status() {
        let st = "Package: a\nStatus: install ok installed\n\nPackage: unattended-upgrades\nStatus: deinstall ok config-files\n";
        assert!(dpkg_installed(st, "a"));
        assert!(!dpkg_installed(st, "unattended-upgrades"));
        assert!(!dpkg_installed(st, "b"));
    }

    #[test]
    fn mode_within_como_bash() {
        assert!(mode_within(0o600, 0o640));
        assert!(mode_within(0o640, 0o640));
        assert!(!mode_within(0o644, 0o640));
        assert!(!mode_within(0o4755, 0o755));
    }
}
