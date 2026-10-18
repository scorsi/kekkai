# One of the three Rust daemons, built by crane. kekkai-control's build.rs needs protoc (0023).
{
  lib,
  protobuf,
  craneLib,
  pname,
}:
let
  common = {
    pname = "kekkai-workspace";
    version = lib.fileContents ../../VERSION;
    strictDeps = true;
    nativeBuildInputs = [ protobuf ];
    PROTOC = "${protobuf}/bin/protoc";
    src = lib.fileset.toSource {
      root = ../..;
      fileset = lib.fileset.unions [
        (craneLib.fileset.commonCargoSources ../../crates)
        (craneLib.fileset.commonCargoSources ../../apps/node)
        (craneLib.fileset.commonCargoSources ../../apps/lighthouse)
        (craneLib.fileset.commonCargoSources ../../apps/relay)
        # A workspace member must be present for cargo to load the manifest.
        (craneLib.fileset.commonCargoSources ../../fuzz)
        ../../Cargo.toml
        ../../Cargo.lock
        ../../proto
      ];
    };
  };
in
craneLib.buildPackage (
  common
  // {
    inherit pname;
    cargoArtifacts = craneLib.buildDepsOnly common;
    cargoExtraArgs = "-p ${pname}";
    meta.mainProgram = pname;
  }
)
