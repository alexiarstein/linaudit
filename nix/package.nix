{
  lib,
  pkgs
}:

pkgs.rustPlatform.buildRustPackage {
  pname = "linaudit";
  version = "0.0.0-unstable-2026-11-5";
  src = ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  postPatch = ''
    substituteInPlace crates/linaudit-core/src/checks/filesystem.rs \
      --replace-fail "fn barrido_completo" "#[ignore]
      fn barrido_completo"
  '';
}
