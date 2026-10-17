# Deployment-agnostic modules (0022). v0.0: options only, the service lands with each daemon.
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
    nixosModules = lib.genAttrs [ "node" "lighthouse" "relay" ] (n: mk "kekkai-${n}");
    darwinModules.node = mk "kekkai-node";
  };
}
