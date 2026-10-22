{
  description = "kekkai (結界, the barrier) — a small authenticated overlay network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    # Test-only: the log and metric validators run by the nixosTests (ADR 0019).
    nisshi = {
      url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/nisshi.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    masu = {
      url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/masu.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      imports = [
        inputs.treefmt-nix.flakeModule
        ./nix/overlay.nix
        ./nix/modules.nix
        ./nix/perSystem.nix
      ];
    };
}
