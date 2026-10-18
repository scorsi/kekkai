# v0.0's trivial integration test: the module installs kekkai-node and it prints VERSION (0020, 0022).
{ pkgs, module }:
pkgs.testers.nixosTest {
  name = "kekkai-node-version";

  nodes.machine = {
    imports = [ module ];
    nixpkgs.pkgs = pkgs;
    services.kekkai-node = {
      enable = true;
      # The service is not exercised here (see two-nodes); the key file may stay absent.
      privateKeyFile = "/run/kekkai-test-key";
      addresses = [ "10.77.0.1/32" ];
    };
  };

  testScript = ''
    machine.succeed("kekkai-node --version | grep -Fx ${pkgs.lib.fileContents ../../VERSION}")
  '';
}
