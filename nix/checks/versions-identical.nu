#!/usr/bin/env nu
# Single version across VERSION and the Cargo workspace (0024). Every binary, the `kekkai` CLI
# included (0033), prints its CARGO_PKG_VERSION, so each must inherit the workspace version.

let version = (open VERSION | str trim)
let cargo_version = (open Cargo.toml | get workspace.package.version)

if $cargo_version != $version {
    print -e $"version mismatch: VERSION=($version) but cargo has ($cargo_version)"
    exit 1
}

for app in [node lighthouse relay cli] {
    if (open $"apps/($app)/Cargo.toml" | get package.version) != {workspace: true} {
        print -e $"version mismatch: apps/($app) does not take version.workspace = true"
        exit 1
    }
}

print $"versions identical: ($version)"
