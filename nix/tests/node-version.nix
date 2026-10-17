# v0.0's trivial integration test: the module installs kekkai-node and it prints VERSION (0020, 0022).
{ pkgs, module }:
pkgs.testers.nixosTest {
  name = "kekkai-node-version";

  nodes.machine = {
    imports = [ module ];
    services.kekkai-node.enable = true;
    nixpkgs.pkgs = pkgs;
  };

  testScript = ''
    machine.succeed("kekkai-node --version | grep -Fx ${pkgs.lib.fileContents ../../VERSION}")
  '';
}
