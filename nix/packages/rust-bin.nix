# A Rust binary of the workspace (the three daemons, the CLI), built by crane. kekkai-control's
# build.rs needs protoc (0023).
{
  lib,
  protobuf,
  craneLib,
  pname,
  mainProgram ? pname,
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
        (craneLib.fileset.commonCargoSources ../../apps/cli-rs)
        # A workspace member must be present for cargo to load the manifest.
        (craneLib.fileset.commonCargoSources ../../fuzz)
        ../../Cargo.toml
        ../../Cargo.lock
        ../../proto
        # The CLI's tests read the shared keygen vectors and the status goldens (0033).
        ../../docs/spec/vectors
        ../../apps/cli-rs/testdata
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
    meta = { inherit mainProgram; };
  }
)
