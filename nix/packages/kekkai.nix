# The Go CLI (0002, 0022).
{ lib, buildGoModule }:
buildGoModule {
  pname = "kekkai";
  version = lib.fileContents ../../VERSION;
  src = lib.fileset.toSource {
    root = ../../apps/cli;
    fileset = ../../apps/cli;
  };
  vendorHash = "sha256-mnZE+J+Am8kQvQpRibOJAWZf60i/MLLsP3BhVFNMPB8=";

  preCheck = "go vet ./...";

  # The module root has no cmd/ subdir, so the binary is named after the directory ("cli").
  postInstall = "mv $out/bin/cli $out/bin/kekkai";
  meta.mainProgram = "kekkai";
}
