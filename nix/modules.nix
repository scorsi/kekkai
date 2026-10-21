# Deployment-agnostic modules (0022). The node modules are nix/modules/node.nix (NixOS, v0.2)
# and nix/modules/darwin-node.nix (nix-darwin, v0.3), the lighthouse is
# nix/modules/lighthouse.nix (v0.4); the relay is options only until its daemon lands.
{ lib, ... }:
let
  mk =
    name:
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      cfg = config.services.${name};
    in
    {
      options.services.${name} = {
        enable = lib.mkEnableOption name;
        package = lib.mkPackageOption pkgs name { };
      };
      config = lib.mkIf cfg.enable { environment.systemPackages = [ cfg.package ]; };
    };
in
{
  flake = {
    nixosModules = {
      node = ./modules/node.nix;
      lighthouse = ./modules/lighthouse.nix;
      relay = mk "kekkai-relay";
    };
    darwinModules.node = ./modules/darwin-node.nix;
  };
}
