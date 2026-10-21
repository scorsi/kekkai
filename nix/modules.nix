# Deployment-agnostic modules (0022). The node modules are nix/modules/node.nix (NixOS, v0.2)
# and nix/modules/darwin-node.nix (nix-darwin, v0.3), the lighthouse is
# nix/modules/lighthouse.nix (v0.4) and the relay nix/modules/relay.nix (v0.5).
{
  flake = {
    nixosModules = {
      node = ./modules/node.nix;
      lighthouse = ./modules/lighthouse.nix;
      relay = ./modules/relay.nix;
    };
    darwinModules.node = ./modules/darwin-node.nix;
  };
}
