# The Go CLI (0002, 0022). The source root is the repository so that the tests read the shared
# keygen vectors under docs/spec/vectors (0015, 0020).
{ lib, buildGoModule }:
buildGoModule {
  pname = "kekkai";
  version = lib.fileContents ../../VERSION;
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../apps/cli
      ../../docs/spec/vectors/keygen.json
    ];
  };
  modRoot = "apps/cli";
  vendorHash = "sha256-mnZE+J+Am8kQvQpRibOJAWZf60i/MLLsP3BhVFNMPB8=";

  preCheck = "go vet ./...";

  # The module root has no cmd/ subdir, so the binary is named after the directory ("cli").
  postInstall = "mv $out/bin/cli $out/bin/kekkai";
  meta.mainProgram = "kekkai";
}
