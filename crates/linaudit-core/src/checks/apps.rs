//! category: apps — port de checks.d/90-apps.sh.
//! Configuración insegura en aplicaciones comunes. Solo emite resultados si la aplicación está presente.
//!
//! Divergencias menores con bash: los archivos de Redis no se repiten en el detalle (bash listaba
//! /etc/redis/redis.conf dos veces), y las reglas `trust` de PostgreSQL se separan con "; ".

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};

use super::Context;
use super::util::{expand_all, find_command, live_command_full, read};
use super::walk::{WalkOpts, glob_match, walk};
use crate::model::{Emitter, ResultExt, Severity::*};
use crate::trc;
use crate::tr;

/// Quita los comentarios `<!-- -->` de un XML (también los multilínea), conservando los saltos de línea.
pub fn xml_nocomments(text: &str) -> String {
    let mut out = String::new();
    let mut in_comment = false;
    for line in text.lines() {
        let mut rest = line;
        loop {
            if in_comment {
                match rest.find("-->") {
                    Some(i) => {
                        rest = &rest[i + 3..];
                        in_comment = false;
                    }
                    None => break,
                }
            } else {
                match rest.find("<!--") {
                    Some(i) => {
                        out.push_str(&rest[..i]);
                        rest = &rest[i + 4..];
                        in_comment = true;
                    }
                    None => {
                        out.push_str(rest);
                        break;
                    }
                }
            }
        }
        out.push('\n');
    }
    out
}

/// (usuario efectivo, línea de comando) de cada proceso, como `ps -eo user=,args=`.
pub fn processes(ctx: &Context) -> Vec<(String, String)> {
    let Ok(dir) = std::fs::read_dir(ctx.path("/proc")) else { return vec![] };
    dir.flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|e| {
            let status = std::fs::read_to_string(e.path().join("status")).ok()?;
            let uid: u32 = status.lines().find(|l| l.starts_with("Uid:"))?.split_whitespace().nth(2)?.parse().ok()?;
            let raw = std::fs::read(e.path().join("cmdline")).ok()?;
            let args = String::from_utf8_lossy(&raw).trim_end_matches('\0').replace('\0', " ");
            let user = crate::system::user_name(uid).unwrap_or_else(|| uid.to_string());
            Some((user, args))
        })
        .collect()
}

fn ci(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).case_insensitive(true).build().expect("regex válida")
}

/// Sin comentarios `#` (para configuraciones estilo shell).
fn strip_hash(text: &str) -> String {
    text.lines().map(|l| l.split('#').next().unwrap_or("")).collect::<Vec<_>>().join("\n")
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    let procs = processes(ctx);
    let mut detected: Vec<&str> = Vec::new();
    tomcat(ctx, em, &procs, &mut detected);
    redis(ctx, em, &procs, &mut detected);
    docker(ctx, em, &mut detected);
    postgres(ctx, em, &mut detected);
    samba(ctx, em, &mut detected);
    web(ctx, em, &mut detected);
    let list = if detected.is_empty() { trc!("applications", "none").to_string() } else { detected.join(" ") };
    em.pass("APP-000", Info, &tr!("Detected applications: {list}", list = list));
}

fn tomcat(ctx: &Context, em: &mut Emitter, procs: &[(String, String)], detected: &mut Vec<&str>) {
    let mut configs = Vec::new();
    for root in ["/opt", "/usr/share", "/usr/local", "/var/lib", "/srv", "/etc", "/home"] {
        walk(ctx, root, &WalkOpts { max_depth: Some(5), ..Default::default() }, &mut |e| {
            if e.name() == "server.xml" && glob_match("*conf*", e.path) {
                if std::fs::read_to_string(e.real).is_ok_and(|t| t.contains("Catalina")) {
                    configs.push(e.path.to_string());
                }
            }
        });
    }
    if configs.is_empty() {
        return;
    }
    detected.push("tomcat");

    static CONNECTOR: LazyLock<Regex> = LazyLock::new(|| {
        ci(r#"<Connector[^>]*protocol="(AJP[^"]*|org.apache.coyote.ajp[^"]*)"[^>]*>"#)
    });
    static SECRET: LazyLock<Regex> = LazyLock::new(|| ci(r#"secret="[^"]+""#));
    static USER: LazyLock<Regex> = LazyLock::new(|| ci(r"<user [^>]*>"));
    static WEAK: LazyLock<Regex> = LazyLock::new(|| {
        ci(r#"password="(tomcat|admin|manager|password|s3cret|12345?6?|changeme|root|secret)""#)
    });

    let (mut ajp, mut weak, mut plain, mut wapps) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for sx in &configs {
        let cdir = sx.rsplit_once('/').map_or("", |(d, _)| d).to_string();
        let parent = cdir.rsplit_once('/').map_or("", |(d, _)| d).to_string();
        // AJP sin secret (Ghostcat, CVE-2020-1938)
        let xml = xml_nocomments(&read(ctx, sx).unwrap_or_default()).replace('\n', " ");
        if CONNECTOR.find_iter(&xml).any(|m| !SECRET.is_match(m.as_str())) {
            ajp.push(sx.clone());
        }
        let ux = format!("{cdir}/tomcat-users.xml");
        if let Some(t) = read(ctx, &ux) {
            let flat = xml_nocomments(&t).replace('\n', " ");
            let users: Vec<&str> = USER.find_iter(&flat).map(|m| m.as_str()).collect();
            if users.iter().any(|u| WEAK.is_match(u)) {
                weak.push(ux.clone());
            }
            if users.iter().any(|u| u.to_lowercase().contains("password=\"")) {
                plain.push(ux.clone());
            }
        }
        let base = parent.rsplit('/').next().unwrap_or("");
        let mut dirs = vec![format!("{parent}/webapps"), format!("/var/lib/{base}/webapps")];
        dirs.extend(expand_all(ctx, &["/var/lib/tomcat*/webapps", "/usr/share/tomcat*/webapps"]));
        for w in dirs.iter().filter(|w| ctx.path(w).is_dir()) {
            for a in ["manager", "host-manager", "examples", "docs"] {
                let p = format!("{w}/{a}");
                if ctx.path(&p).is_dir() {
                    wapps.push(p);
                }
            }
        }
    }
    ajp.sort();
    ajp.dedup();
    wapps.sort();
    wapps.dedup();
    wapps.truncate(6);

    if ajp.is_empty() {
        em.pass("APP-001", High, tr!("Tomcat: no AJP connector without a secret"));
    } else {
        em.fail("APP-001", High, tr!("Tomcat: AJP connector without a secret (Ghostcat)"))
            .with_detail(ajp.join(" "))
            .with_fix(tr!("Disable AJP or set address=127.0.0.1 and a secret"));
    }
    if weak.is_empty() {
        em.pass("APP-002", Critical, tr!("Tomcat: no default credentials in tomcat-users.xml"));
    } else {
        em.fail("APP-002", Critical, tr!("Tomcat: users with a default/trivial password"))
            .with_detail(weak.join(" "))
            .with_fix(tr!("Change the password or remove the users"));
    }
    if plain.is_empty() {
        em.pass("APP-003", Low, tr!("Tomcat: user passwords are not in plaintext"));
    } else {
        em.warn("APP-003", Low, tr!("Tomcat: plaintext passwords in tomcat-users.xml"))
            .with_detail(plain.join(" "))
            .with_fix(tr!("Use a CredentialHandler with a digest (SHA-256/bcrypt) in the Realm"));
    }
    if wapps.is_empty() {
        em.pass("APP-004", Medium, tr!("Tomcat: no manager/examples/docs deployed"));
    } else {
        em.warn("APP-004", Medium, tr!("Tomcat: admin or example applications deployed"))
            .with_detail(wapps.join(" "))
            .with_fix(tr!("Remove examples/docs; restrict manager by IP or remove it in production"));
    }
    match procs.iter().find(|(u, a)| u == "root" && a.contains("catalina")) {
        None => {
            em.pass("APP-005", High, tr!("Tomcat does not run as root"));
        }
        Some((u, a)) => {
            let line: String = format!("{u:<8} {a}").chars().take(80).collect();
            em.fail("APP-005", High, tr!("Tomcat runs as root"))
                .with_detail(format!("root: {line}"))
                .with_fix(tr!("Run it as an unprivileged service user (port <1024 via proxy/authbind)"));
        }
    }
}

/// true si la configuración de Redis lo deja expuesto a la red sin autenticación.
pub fn redis_exposed(conf: &str) -> bool {
    let c = strip_hash(conf);
    let mut binds = Vec::new();
    let mut protected = String::new();
    let mut auth = false;
    for l in c.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(k) = f.first().map(|k| k.to_lowercase()) else { continue };
        match k.as_str() {
            "bind" => binds.extend(f[1..].iter().map(|s| s.to_string())),
            "protected-mode" => protected = f.get(1).map(|v| v.to_lowercase()).unwrap_or_default(),
            "requirepass" | "aclfile" | "user" if f.len() > 1 || l.ends_with(char::is_whitespace) => auth = true,
            _ => {}
        }
    }
    let loopback = |b: &str| {
        let b = b.strip_prefix('-').unwrap_or(b);
        b.starts_with("127.") || b == "::1" || b == "localhost" || b.is_empty()
    };
    let nonloop = binds.iter().any(|b| !loopback(b));
    (nonloop || (binds.is_empty() && protected == "no")) && !auth
}

fn redis(ctx: &Context, em: &mut Emitter, procs: &[(String, String)], detected: &mut Vec<&str>) {
    let mut confs: Vec<String> = vec!["/etc/redis/redis.conf".into(), "/etc/redis.conf".into()];
    confs.extend(expand_all(ctx, &["/etc/redis/*.conf", "/usr/local/etc/redis/*.conf"]));
    confs.retain(|f| std::fs::File::open(ctx.path(f)).is_ok());
    let mut seen = std::collections::HashSet::new();
    confs.retain(|f| seen.insert(f.clone()));
    let running = procs.iter().any(|(_, a)| a.contains("redis-server"));
    if confs.is_empty() && !running {
        return;
    }
    detected.push("redis");
    let exposed: Vec<&str> =
        confs.iter().filter(|f| read(ctx, f).is_some_and(|t| redis_exposed(&t))).map(String::as_str).collect();
    if exposed.is_empty() {
        em.pass("APP-010", Critical, tr!("Redis: no unauthenticated network exposure"));
    } else {
        em.fail("APP-010", Critical, tr!("Redis exposed to the network WITHOUT authentication"))
            .with_detail(exposed.join(" "))
            .with_fix(tr!("bind 127.0.0.1 or requirepass/ACL + firewall; never protected-mode no without a password"));
    }
    if procs.iter().any(|(u, a)| u == "root" && a.contains("redis-server")) {
        em.fail("APP-011", High, tr!("Redis runs as root")).with_detail("root: redis-server").with_fix(tr!("Run it as the 'redis' user"));
    } else {
        em.pass("APP-011", High, tr!("Redis does not run as root"));
    }
}

fn docker(ctx: &Context, em: &mut Emitter, detected: &mut Vec<&str>) {
    let sock = std::fs::metadata(ctx.path("/var/run/docker.sock")).ok().filter(|m| m.file_type().is_socket());
    let have_docker = ctx.is_live() && find_command("docker").is_some();
    if !have_docker && sock.is_none() {
        return;
    }
    detected.push("docker");
    if let Some(m) = sock {
        let mode = m.mode() & 0o7777;
        if mode & 0o002 != 0 {
            em.fail("APP-020", Critical, tr!("docker.sock writable by everyone (root for any user)"))
                .with_detail(tr!("mode {mode}", mode = format!("{mode:o}")))
                .with_fix("chmod 660 /var/run/docker.sock");
        } else {
            em.pass("APP-020", Critical, tr!("docker.sock is not world-writable"));
        }
    }
    let members = read(ctx, "/etc/group")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("docker:"))
        .and_then(|l| l.split(':').nth(3))
        .unwrap_or("")
        .to_string();
    if members.is_empty() {
        em.pass("APP-021", Low, tr!("docker group has no members"));
    } else {
        em.warn("APP-021", Low, tr!("docker group members (equivalent to root)"))
            .with_detail(members)
            .with_fix(tr!("Keep it to a minimum; consider rootless Docker or scoped sudo"));
    }
    if !(ctx.root && have_docker) || !live_command_full(ctx, "docker", &["info"], &[]).is_some_and(|o| o.ok) {
        return;
    }
    let ids: Vec<String> = live_command_full(ctx, "docker", &["ps", "-q"], &[])
        .map(|o| o.stdout.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return;
    }
    let mut args = vec![
        "inspect",
        "--format",
        "{{.Name}} priv={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} sock={{range .Mounts}}{{.Source}},{{end}}",
    ];
    args.extend(ids.iter().map(String::as_str));
    let out = live_command_full(ctx, "docker", &args, &[]).map(|o| o.stdout).unwrap_or_default();
    let x: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("priv=true") || l.contains("pid=host") || l.contains("docker.sock"))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    if x.is_empty() {
        em.pass("APP-022", High, tr!("Containers without privileged/pid=host/docker.sock"));
    } else {
        em.warn("APP-022", High, tr!("Containers with host privileges (privileged, pid=host or docker.sock)"))
            .with_detail(x.join(" "))
            .with_fix(tr!("Remove --privileged and the docker.sock mount unless justified"));
    }
}

fn postgres(ctx: &Context, em: &mut Emitter, detected: &mut Vec<&str>) {
    let mut hba = expand_all(
        ctx,
        &["/etc/postgresql/*/*/pg_hba.conf", "/var/lib/pgsql/*/data/pg_hba.conf", "/var/lib/pgsql/data/pg_hba.conf"],
    );
    hba.sort();
    if hba.is_empty() {
        return;
    }
    detected.push("postgresql");
    let (mut trust, mut open) = (Vec::new(), Vec::new());
    for f in &hba {
        for l in strip_hash(&read(ctx, f).unwrap_or_default()).lines() {
            let w: Vec<&str> = l.split_whitespace().collect();
            if !w.first().is_some_and(|t| t.starts_with("host")) {
                continue;
            }
            if w.last() == Some(&"trust") {
                trust.push(format!("{f}: {l}"));
            }
            if matches!(w.get(3), Some(&"0.0.0.0/0" | &"::/0")) {
                open.push(f.clone());
            }
        }
    }
    trust.truncate(3);
    open.dedup();
    if trust.is_empty() {
        em.pass("APP-030", High, tr!("PostgreSQL: no 'trust' for network connections"));
    } else {
        em.fail("APP-030", High, tr!("PostgreSQL: pg_hba.conf allows 'trust' over the network")).with_detail(trust.join("; ")).with_fix(tr!("Use scram-sha-256"));
    }
    if open.is_empty() {
        em.pass("APP-031", Medium, tr!("PostgreSQL: pg_hba.conf has no rules open to 0.0.0.0/0"));
    } else {
        em.warn("APP-031", Medium, tr!("PostgreSQL: rules open to any source (0.0.0.0/0)"))
            .with_detail(open.join(" "))
            .with_fix(tr!("Restrict to the application networks"));
    }
}

fn samba(ctx: &Context, em: &mut Emitter, detected: &mut Vec<&str>) {
    let Some(conf) = read(ctx, "/etc/samba/smb.conf") else { return };
    detected.push("samba");
    static GUEST: LazyLock<Regex> = LazyLock::new(|| {
        ci(r"guest ok[[:space:]]*=[[:space:]]*(yes|true)|map to guest[[:space:]]*=[[:space:]]*bad user|security[[:space:]]*=[[:space:]]*share")
    });
    let guest = conf.lines().map(|l| l.split(['#', ';']).next().unwrap_or("")).any(|l| GUEST.is_match(l));
    if guest {
        em.warn("APP-040", Medium, tr!("Samba allows guest access"))
            .with_detail("/etc/samba/smb.conf")
            .with_fix(tr!("guest ok = no; review 'map to guest'"));
    } else {
        em.pass("APP-040", Medium, tr!("Samba without guest access"));
    }
}

/// Como `grep -r`: archivos de un árbol sin seguir symlinks, en orden de recorrido.
fn tree_files(ctx: &Context, dir: &str) -> Vec<String> {
    let mut v = Vec::new();
    walk(ctx, dir, &WalkOpts::default(), &mut |e| {
        if e.is_file() {
            v.push(e.path.to_string());
        }
    });
    v
}

/// "archivo:línea" de las líneas que coinciden con `re` y no con `exclude`, hasta `max`.
fn grep_tree(ctx: &Context, dir: &str, re: &Regex, exclude: Option<&Regex>, max: usize) -> Vec<String> {
    super::util::grep_files(ctx, &tree_files(ctx, dir), re, None)
        .into_iter()
        .filter(|(_, _, l)| exclude.is_none_or(|x| !x.is_match(l)))
        .take(max)
        .map(|(f, n, _)| format!("{f}:{n}"))
        .collect()
}

fn web(ctx: &Context, em: &mut Emitter, detected: &mut Vec<&str>) {
    // Apache se detecta por su config principal, no por el directorio: en Debian
    // javascript-common deja /etc/apache2/conf-available/ aunque Apache no esté instalado.
    let apache = [("/etc/apache2", "/etc/apache2/apache2.conf"), ("/etc/httpd", "/etc/httpd/conf/httpd.conf")]
        .into_iter()
        .find(|(_, conf)| ctx.path(conf).is_file())
        .map(|(dir, _)| dir);
    if let Some(ap) = apache {
        detected.push("apache");
        let tokens = Regex::new(r"^[[:space:]]*ServerTokens[[:space:]]+(Prod|ProductOnly)").expect("regex válida");
        if grep_tree(ctx, ap, &tokens, None, 1).is_empty() {
            em.warn("APP-050", Low, tr!("Apache exposes its version (ServerTokens)")).with_detail(ap).with_fix(tr!("ServerTokens Prod and ServerSignature Off"));
        } else {
            em.pass("APP-050", Low, "Apache: ServerTokens Prod");
        }
        let indexes = Regex::new(r"^[[:space:]]*Options[[:space:]].*[[:space:]+]?Indexes").expect("regex válida");
        let minus = Regex::new(r"Options.*-Indexes").expect("regex válida");
        let x = grep_tree(ctx, ap, &indexes, Some(&minus), 5);
        if x.is_empty() {
            em.pass("APP-051", Medium, tr!("Apache: no directory listing (Options Indexes)"));
        } else {
            em.warn("APP-051", Medium, tr!("Apache: directory listing enabled")).with_detail(x.join(" ")).with_fix("Options -Indexes");
        }
    }
    if ctx.path("/etc/nginx").is_dir() {
        detected.push("nginx");
        let tokens = Regex::new(r"^[[:space:]]*server_tokens[[:space:]]+off").expect("regex válida");
        if grep_tree(ctx, "/etc/nginx", &tokens, None, 1).is_empty() {
            em.warn("APP-052", Low, tr!("nginx exposes its version (server_tokens)")).with_detail("/etc/nginx").with_fix("server_tokens off;");
        } else {
            em.pass("APP-052", Low, "nginx: server_tokens off");
        }
        let auto = Regex::new(r"^[[:space:]]*autoindex[[:space:]]+on").expect("regex válida");
        let x = grep_tree(ctx, "/etc/nginx", &auto, None, 5);
        if x.is_empty() {
            em.pass("APP-053", Medium, tr!("nginx: no autoindex"));
        } else {
            em.warn("APP-053", Medium, tr!("nginx: autoindex enabled")).with_detail(x.join(" ")).with_fix("autoindex off;");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::Status;

    #[test]
    fn sin_aplicaciones() {
        let r = Fixture::new().run(run);
        assert_eq!(r.len(), 1);
        assert_eq!(r["APP-000"].title, "Aplicaciones detectadas: ninguna");
    }

    #[test]
    fn xml_sin_comentarios() {
        let x = xml_nocomments("a<!-- b\nc --> d <!-- e --> f\ng");
        assert_eq!(x, "a\n d  f\ng\n");
    }

    #[test]
    fn tomcat_inseguro() {
        let f = Fixture::new();
        f.file(
            "/opt/tomcat/conf/server.xml",
            "<Server><Service name=\"Catalina\">\n<!-- <Connector port=\"8009\" protocol=\"AJP/1.3\" secret=\"x\"/> -->\n\
             <Connector port=\"8009\" protocol=\"AJP/1.3\"\n address=\"0.0.0.0\" />\n</Service></Server>\n",
        )
        .file(
            "/opt/tomcat/conf/tomcat-users.xml",
            "<tomcat-users>\n<!-- <user username=\"x\" password=\"secreto-largo\"/> -->\n<user username=\"admin\" password=\"s3cret\" roles=\"manager-gui\"/>\n</tomcat-users>\n",
        )
        .dir("/opt/tomcat/webapps/manager")
        .dir("/opt/tomcat/webapps/examples")
        .dir("/opt/tomcat/webapps/ROOT");
        let r = f.run(run);
        assert_eq!(r["APP-001"].status, Status::Fail);
        assert_eq!(r["APP-002"].detail, "/opt/tomcat/conf/tomcat-users.xml");
        assert_eq!(r["APP-003"].status, Status::Warn);
        assert_eq!(r["APP-004"].detail, "/opt/tomcat/webapps/examples /opt/tomcat/webapps/manager");
        assert_eq!(r["APP-000"].title, "Aplicaciones detectadas: tomcat");
    }

    #[test]
    fn tomcat_con_secret_esta_bien() {
        let f = Fixture::new();
        f.file(
            "/opt/tomcat/conf/server.xml",
            "<Service name=\"Catalina\"><Connector protocol=\"AJP/1.3\" secret=\"largo\" address=\"127.0.0.1\"/></Service>",
        );
        assert_eq!(f.run(run)["APP-001"].status, Status::Pass);
    }

    #[test]
    fn redis_expuesto() {
        assert!(redis_exposed("bind 0.0.0.0\nprotected-mode yes\n"));
        assert!(redis_exposed("protected-mode no\n"));
        assert!(!redis_exposed("bind 127.0.0.1 -::1\n"));
        assert!(!redis_exposed("bind 0.0.0.0\nrequirepass algo-largo\n"));
        assert!(!redis_exposed("# bind 0.0.0.0\n"));
    }

    #[test]
    fn redis_y_procesos_como_root() {
        let f = Fixture::new();
        f.file("/etc/redis/redis.conf", "bind 0.0.0.0\n")
            .file("/proc/42/status", "Name:\tredis-server\nUid:\t0\t0\t0\t0\n")
            .file("/proc/42/cmdline", "/usr/bin/redis-server\0*:6379\0");
        let r = f.run(run);
        assert_eq!(r["APP-010"].detail, "/etc/redis/redis.conf", "sin repetir el archivo");
        assert_eq!(r["APP-011"].status, Status::Fail);
    }

    #[test]
    fn postgres_samba_apache_nginx() {
        let f = Fixture::new();
        f.file(
            "/etc/postgresql/16/main/pg_hba.conf",
            "local all postgres peer\n# host all all 0.0.0.0/0 trust\nhost all all 0.0.0.0/0 scram-sha-256\nhost all all 10.0.0.0/8 trust\n",
        )
        .file("/etc/samba/smb.conf", "[global]\n; guest ok = yes\n   map to guest = bad user\n")
        .file("/etc/apache2/apache2.conf", "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n</Directory>\n<Directory /srv>\n Options -Indexes\n</Directory>\n")
        .file("/etc/apache2/conf-available/security.conf", "ServerTokens OS\n#ServerTokens Prod\n")
        .file("/etc/nginx/nginx.conf", "http {\n\tserver_tokens off;\n}\n")
        .file("/etc/nginx/sites-available/default", "location / {\n    autoindex on;\n}\n")
        .file("/etc/group", "docker:x:999:ana,beto\n");
        let r = f.run(run);
        assert_eq!(r["APP-030"].detail, "/etc/postgresql/16/main/pg_hba.conf: host all all 10.0.0.0/8 trust");
        assert_eq!(r["APP-031"].detail, "/etc/postgresql/16/main/pg_hba.conf");
        assert_eq!(r["APP-040"].status, Status::Warn);
        assert_eq!(r["APP-050"].status, Status::Warn);
        assert_eq!(r["APP-051"].detail, "/etc/apache2/apache2.conf:2");
        assert_eq!(r["APP-052"].status, Status::Pass);
        assert_eq!(r["APP-053"].detail, "/etc/nginx/sites-available/default:2");
        assert!(!r.contains_key("APP-021"), "sin docker no se mira el grupo");
        assert_eq!(r["APP-000"].title, "Aplicaciones detectadas: postgresql samba apache nginx");
    }

    #[test]
    fn javascript_common_no_es_apache() {
        // Debian: javascript-common deja este conffile sin que Apache esté instalado.
        let f = Fixture::new();
        f.file("/etc/apache2/conf-available/javascript-common.conf", "Alias /javascript /usr/share/javascript/\n");
        let r = f.run(run);
        assert!(!r.contains_key("APP-050"), "sin apache2.conf no hay Apache");
        assert!(!r.contains_key("APP-051"));
        assert_eq!(r["APP-000"].title, "Aplicaciones detectadas: ninguna");
    }
}
