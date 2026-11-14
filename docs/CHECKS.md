# Checks incluidos

Peso en el puntaje: CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1, INFO=0.
El título es el del caso "cumple"; cuando falla, el reporte muestra el detalle y cómo arreglarlo.

## accounts

| ID | Severidad | Qué verifica |
|---|---|---|
| ACC-001 | CRITICAL | Solo root tiene UID 0 |
| ACC-002 | CRITICAL | Ninguna cuenta con password vacío |
| ACC-003 | HIGH | Passwords en /etc/shadow (no en passwd) |
| ACC-004 | HIGH | sudo sin NOPASSWD:ALL |
| ACC-005 | MEDIUM | sudo sin NOPASSWD acotado |
| ACC-006 | MEDIUM | Cuentas de servicio sin shell interactiva |
| ACC-007 | MEDIUM | Cuentas de servicio sin authorized_keys |
| ACC-008 | MEDIUM | Sin UIDs duplicados |
| ACC-009 | MEDIUM | PASS_MAX_DAYS <= 365 |
| ACC-010 | MEDIUM | Longitud mínima de password >= 12 |
| ACC-011 | HIGH | Sin hashes MD5/DES en /etc/shadow |
| ACC-012 | MEDIUM | ENCRYPT_METHOD fuerte |

## ssh

| ID | Severidad | Qué verifica |
|---|---|---|
| SSH-001 | HIGH | Login directo de root deshabilitado |
| SSH-002 | MEDIUM | Autenticación por password deshabilitada |
| SSH-003 | CRITICAL | PermitEmptyPasswords deshabilitado |
| SSH-004 | LOW | MaxAuthTries razonable |
| SSH-005 | LOW | X11Forwarding deshabilitado |
| SSH-006 | MEDIUM | Sin algoritmos criptográficos débiles |
| SSH-007 | LOW | LoginGraceTime <= 60s |
| SSH-008 | LOW | Timeout de sesiones inactivas |
| SSH-009 | MEDIUM | GatewayPorts deshabilitado |
| SSH-010 | MEDIUM | Ningún bloque Match reabre root/passwords vacíos |
| SSH-011 | LOW | Banner legal configurado |
| SSH-012 | HIGH | HostbasedAuthentication deshabilitado |
| SSH-013 | MEDIUM | PermitUserEnvironment deshabilitado |
| SSH-014 | MEDIUM | Permisos de sshd_config |
| SSH-015 | HIGH | Claves privadas de host con permisos correctos |
| SSH-016 | MEDIUM | Sin clave de host DSA |

## filesystem

| ID | Severidad | Qué verifica |
|---|---|---|
| FS-001 | CRITICAL | Permisos de /etc/shadow |
| FS-002 | HIGH | Permisos de /etc/gshadow |
| FS-003 | MEDIUM | Permisos de /etc/passwd |
| FS-004 | MEDIUM | Permisos de /etc/group |
| FS-005 | HIGH | Permisos de /etc/sudoers |
| FS-006 | MEDIUM | /tmp montado con nodev, nosuid y noexec |
| FS-007 | MEDIUM | /var/tmp montado con nodev, nosuid y noexec |
| FS-008 | MEDIUM | /dev/shm montado con nodev, nosuid y noexec |
| FS-009 | HIGH | Ningún home es world-writable |
| FS-010 | LOW | Homes con permisos restrictivos (<=750) |
| FS-011 | HIGH | Sin capabilities peligrosas en binarios |
| FS-012 | HIGH | Sin SUID/SGID en tmp, home, www |
| FS-013 | CRITICAL | Sin SUID en binarios peligrosos (GTFOBins) |
| FS-014 | HIGH | Todos los SUID/SGID pertenecen a paquetes |
| FS-015 | HIGH | Sin archivos world-writable en rutas del sistema |
| FS-016 | MEDIUM | Sin archivos world-writable fuera del sistema |
| FS-017 | MEDIUM | Directorios world-writable con sticky bit |
| FS-018 | MEDIUM | Sin archivos huérfanos (sin dueño/grupo) |
| FS-019 | MEDIUM | Snapshots de backup (/timeshift, /.snapshots) no accesibles para otros usuarios |

## secrets

| ID | Severidad | Qué verifica |
|---|---|---|
| SEC-001 | MEDIUM | Sin credenciales evidentes en texto plano |
| SEC-002 | HIGH | Sin credenciales embebidas en URLs |
| SEC-003 | CRITICAL | Claves privadas no legibles por todos ($nk halladas) |
| SEC-004 | MEDIUM | Claves SSH de usuarios con passphrase |
| SEC-005 | HIGH | Archivos de credenciales con modo 600 |
| SEC-006 | MEDIUM | Historiales de shell sin credenciales evidentes |
| SEC-007 | HIGH | Sin credenciales evidentes en units de systemd ni cron |
| SEC-008 | HIGH | Archivos con posibles credenciales no son legibles por todos |

## network

| ID | Severidad | Qué verifica |
|---|---|---|
| NET-001 | HIGH | Firewall local activo |
| NET-002 | MEDIUM | Firewall con política por defecto restrictiva |
| NET-003 | HIGH | Sin servicios inseguros en claro expuestos (telnet/ftp/rsh/tftp/vnc) |
| NET-004 | CRITICAL | API de Docker sin TLS no expuesta |
| NET-005 | MEDIUM | Bases de datos/colas solo en loopback |
| NET-006 | INFO | Superficie de red |
| NET-007 | MEDIUM | ip_forward deshabilitado |
| NET-008 | MEDIUM | Rechaza ICMP redirects |
| NET-009 | LOW | No envía ICMP redirects |
| NET-010 | MEDIUM | Rechaza source routing |
| NET-011 | MEDIUM | Reverse path filtering activo |
| NET-012 | MEDIUM | SYN cookies activas |
| NET-013 | LOW | Ignora ICMP echo a broadcast |
| NET-014 | LOW | Registra paquetes marcianos |
| NET-015 | HIGH | Exports NFS sin no_root_squash ni comodines |
| NET-016 | HIGH | SNMP sin communities por defecto |
| NET-017 | HIGH | Sin confianza r-commands (hosts.equiv / .rhosts) |

## patching

| ID | Severidad | Qué verifica |
|---|---|---|
| PAT-001 | HIGH | Sin errata de seguridad pendientes (según la caché local) |
| PAT-002 | MEDIUM | Índice de paquetes actualizado hace $d días |
| PAT-003 | MEDIUM | Mecanismo de actualización automática habilitado |
| PAT-004 | MEDIUM | Corre el kernel más reciente instalado |
| PAT-005 | HIGH | $OS_PRETTY dentro de soporte hasta $eol |
| PAT-006 | HIGH | Repositorios con verificación de firma |
| PAT-007 | INFO | Orígenes de paquetes no estándar |
| PAT-008 | MEDIUM | Sin CVEs sin corregir en servicios de red (requiere debsecan; consulta security-tracker.debian.org) |

## hardening

| ID | Severidad | Qué verifica |
|---|---|---|
| HRD-001 | HIGH | AppArmor activo |
| HRD-002 | MEDIUM | auditd en ejecución |
| HRD-003 | LOW | auditd con reglas cargadas |
| HRD-004 | MEDIUM | Sincronización horaria activa |
| HRD-005 | MEDIUM | journald persistente activo |
| HRD-006 | MEDIUM | Logs enviados a un colector remoto |
| HRD-007 | MEDIUM | ASLR completo |
| HRD-008 | LOW | kptr_restrict activo |
| HRD-009 | LOW | dmesg restringido |
| HRD-010 | MEDIUM | Sin core dumps de procesos setuid |
| HRD-011 | LOW | Protección de hardlinks |
| HRD-012 | LOW | Protección de symlinks |
| HRD-013 | LOW | ptrace restringido (Yama) |
| HRD-014 | MEDIUM | Sin servicios típicamente innecesarios activos |
| HRD-015 | LOW | Protección anti fuerza bruta activa |
| HRD-016 | LOW | umask por defecto restrictivo |
| HRD-017 | LOW | Banners locales sin datos del sistema |

## persistence

| ID | Severidad | Qué verifica |
|---|---|---|
| PER-001 | CRITICAL | /etc/ld.so.preload ausente o vacío |
| PER-002 | HIGH | Sin LD_PRELOAD persistente |
| PER-003 | HIGH | Cron sin patrones de reverse shell/descarga-y-ejecución |
| PER-004 | MEDIUM | Permisos de cron correctos |
| PER-005 | HIGH | Units de systemd sin ejecutables en /tmp, /dev/shm ni ocultos |
| PER-006 | LOW | root sin authorized_keys |
| PER-007 | HIGH | Binarios de sistema coinciden con los paquetes (${cmd[*]}) |
| PER-008 | HIGH | Scripts de login sin patrones sospechosos |
| PER-009 | CRITICAL | PAM sin 'auth sufficient pam_permit.so' |
| PER-010 | MEDIUM | PAM sin pam_exec |
| PER-011 | LOW | rc.local sin comandos |
| PER-012 | MEDIUM | Sin módulos de kernel externos ni sin firmar |
| PER-013 | HIGH | Ningún proceso corre desde /tmp, /dev/shm ni memfd |
| PER-014 | LOW | Ningún proceso corre con binario borrado/reemplazado |
| PER-015 | HIGH | Ningún proceso corre desde memoria anónima (memfd) |

## apps

| ID | Severidad | Qué verifica |
|---|---|---|
| APP-000 | INFO | Aplicaciones detectadas |
| APP-001 | HIGH | Tomcat: sin conector AJP sin secreto |
| APP-002 | CRITICAL | Tomcat: sin credenciales por defecto en tomcat-users.xml |
| APP-003 | LOW | Tomcat: passwords de usuarios no están en texto plano |
| APP-004 | MEDIUM | Tomcat: sin manager/examples/docs desplegados |
| APP-005 | HIGH | Tomcat no corre como root |
| APP-010 | CRITICAL | Redis: sin exposición de red sin autenticación |
| APP-011 | HIGH | Redis no corre como root |
| APP-020 | CRITICAL | docker.sock no es world-writable |
| APP-021 | LOW | Grupo docker sin miembros |
| APP-022 | HIGH | Contenedores sin privileged/pid=host/docker.sock |
| APP-030 | HIGH | PostgreSQL: sin 'trust' para conexiones de red |
| APP-031 | MEDIUM | PostgreSQL: pg_hba.conf sin reglas abiertas a 0.0.0.0/0 |
| APP-040 | MEDIUM | Samba sin acceso de invitados |
| APP-050 | LOW | Apache: ServerTokens Prod |
| APP-051 | MEDIUM | Apache: sin directory listing (Options Indexes) |
| APP-052 | LOW | nginx: server_tokens off |
| APP-053 | MEDIUM | nginx: sin autoindex |

## sca

Controles cargados dinámicamente desde archivos de políticas YAML en `/etc/linaudit/rules.d/` o directorios especificados mediante `--rules-dir`. Compatible con la sintaxis de Security Configuration Assessment (SCA) de Atomicorp / AWP Agent / Wazuh.

| Sintaxis de regla | Descripción |
|---|---|
| `c:<cmd> -> r:<regex>` | El comando `<cmd>` debe devolver una salida que coincida con `<regex>` |
| `not c:<cmd> -> r:<regex>` | La salida del comando `<cmd>` no debe coincidir con `<regex>` |
| `f:<archivo> -> r:<regex>` | El contenido de `<archivo>` debe coincidir con `<regex>` |
| `not f:<archivo> -> r:<regex>` | El contenido de `<archivo>` no debe coincidir con `<regex>` |
| `d:<directorio> -> <ext> -> r:<regex>` | Los archivos con extensión `<ext>` en `<directorio>` deben coincidir con `<regex>` |

Condiciones admitidas:
- `all`: Todas las reglas deben cumplirse.
- `any`: Al menos una regla debe cumplirse.
- `none`: Ninguna regla debe cumplirse (ideal para detectar configuraciones vulnerables o credenciales expuestas).

