%global debug_package %{nil}

Name:           linaudit
Version:        0.2.0
Release:        1%{?dist}
Summary:        Read-only Linux security auditor with a 1-to-10 posture score
License:        AGPL-3.0-or-later
URL:            https://lexiworks.dev/linaudit

# Default tarball name matches user workflow (e.g. rpmbuild -ta libaudit.tar.gz)
# Override with: --define "_sourcetar <tarball>"
Source0:        %{?_sourcetar}%{!?_sourcetar:libaudit.tar.gz}

BuildRequires:  cargo >= 1.85
BuildRequires:  rust >= 1.85
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros

Recommends:     iproute
Suggests:       openssh-clients
Suggests:       libcap

%description
linaudit audits a Linux machine from an attacker or auditor perspective,
scoring security posture from 1 (worst) to 10 (best). It runs over 100
read-only checks across accounts, SSH, permissions, secrets, network,
packages, compromise indicators, system hardening, and services.

%prep
%setup -q -c -T
tar -xf %{SOURCE0}
shopt -s dotglob nullglob
dirs=(*)
if [ ${#dirs[@]} -eq 1 ] && [ -d "${dirs[0]}" ]; then
    DIR="${dirs[0]}"
    mv "$DIR"/* .
    rmdir "$DIR"
fi
shopt -u dotglob nullglob

%build
cargo build --release --workspace

%check
cargo test --release --workspace

%install
# Binary
install -D -p -m 0755 target/release/linaudit %{buildroot}%{_bindir}/linaudit

# Configuration files
install -D -p -m 0644 etc/config.toml %{buildroot}%{_sysconfdir}/linaudit/config.toml
install -D -p -m 0644 etc/waivers.conf %{buildroot}%{_sysconfdir}/linaudit/waivers.conf

# State directory
install -d -m 0700 %{buildroot}%{_sharedstatedir}/linaudit

# Systemd units
install -D -p -m 0644 contrib/systemd/linaudit.service %{buildroot}%{_unitdir}/linaudit.service
install -D -p -m 0644 contrib/systemd/linaudit.timer %{buildroot}%{_unitdir}/linaudit.timer

# Man pages
install -D -p -m 0644 doc/linaudit.1 %{buildroot}%{_mandir}/man1/linaudit.1
install -D -p -m 0644 doc/linaudit.es.1 %{buildroot}%{_mandir}/es/man1/linaudit.1

# Shell completions generated from built binary
install -d %{buildroot}%{_datadir}/bash-completion/completions \
           %{buildroot}%{_datadir}/zsh/site-functions \
           %{buildroot}%{_datadir}/fish/vendor_completions.d

LINAUDIT_LANG=en ./target/release/linaudit --completions bash > %{buildroot}%{_datadir}/bash-completion/completions/linaudit
LINAUDIT_LANG=en ./target/release/linaudit --completions zsh > %{buildroot}%{_datadir}/zsh/site-functions/_linaudit
LINAUDIT_LANG=en ./target/release/linaudit --completions fish > %{buildroot}%{_datadir}/fish/vendor_completions.d/linaudit.fish

%post
%systemd_post linaudit.timer linaudit.service

%preun
%systemd_preun linaudit.timer linaudit.service

%postun
%systemd_postun_with_restart linaudit.timer

%files
%license LICENSE
%doc README.md README.es.md docs/CHECKS.md
%{_bindir}/linaudit
%dir %{_sysconfdir}/linaudit
%config(noreplace) %{_sysconfdir}/linaudit/config.toml
%config(noreplace) %{_sysconfdir}/linaudit/waivers.conf
%dir %attr(0700,root,root) %{_sharedstatedir}/linaudit
%{_unitdir}/linaudit.service
%{_unitdir}/linaudit.timer
%{_mandir}/man1/linaudit.1*
%{_mandir}/es/man1/linaudit.1*
%{_datadir}/bash-completion/completions/linaudit
%{_datadir}/zsh/site-functions/_linaudit
%{_datadir}/fish/vendor_completions.d/linaudit.fish

%changelog
* Thu Nov 12 2026 Scott R. Shinn <scott@atomicrocketturtle.com> - 0.2.0-1
- Initial RPM packaging for linaudit 0.2.0
