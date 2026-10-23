# overlays.default (0022): the packages, so modules can use `mkPackageOption pkgs`.
{ inputs, ... }:
{
  flake.overlays.default =
    final: _prev:
    let
      craneLib = inputs.crane.mkLib final;
      rust = pname: final.callPackage ./packages/rust-bin.nix { inherit craneLib pname; };
    in
    {
      kekkai-node = rust "kekkai-node";
      kekkai-lighthouse = rust "kekkai-lighthouse";
      kekkai-relay = rust "kekkai-relay";
      kekkai = rust "kekkai";
    };
}
