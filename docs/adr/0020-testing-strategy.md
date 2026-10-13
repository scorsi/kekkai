# ADR 0020 — Testing strategy

Status: Accepted — 2026-10-13

## Context

A cryptographic state machine, NAT behaviour and two infrastructure roles must be proven before touching real hosts. The author's CI runs on Forgejo runners; `nixosTest` needs KVM.

## Options considered

- Rely on `nixosTest` for everything: slow, Linux-only, and NAT scenarios are hard to make deterministic.
- Five tiers, the first four in `nix flake check`, the fifth manual.

## Decision

1. **Unit and property tests** (proptest) inside the crate builds, all systems. Includes Noise IKpsk2 vectors from `snow`, the shared keygen vectors (Rust and Go), wire-format vectors; vectors are JSON files under `docs/spec/vectors/` loaded by both test suites.
2. **Deterministic simulation**: Rust integration tests running several sans-IO cores through a simulated network (loss, reordering, duplication, delay, clock drift, NAT emulated by address rewriting), fixed seed, all systems. Hole punching, relay fallback and roaming are proven here first.
3. **Fuzzing**: cargo-fuzz targets on the parsers (outer header, TLV lists, inner messages, TOML config). `nix flake check` only **replays the committed corpus** deterministically. Fuzzing itself runs by hand (`nix run .#fuzz -- <target> <duration>`) and new findings are added to the corpus. No scheduled fuzz job in v0.
4. **`nixosTest`**: Linux only, KVM required, `lib.optionalAttrs` on Linux systems. NAT is simulated with router nodes running nftables: `masquerade` for a cone NAT, `masquerade fully-random` for a symmetric one. Tests assert on `kekkai status --json`, never on `ping` alone.
5. **Real network**: the manual checklist of the real-network milestone. A breakage seen on the real network becomes a simulation or `nixosTest` case before it is fixed.

Where `nixosTest`s run: on a Linux Forgejo runner labelled **`kvm`**. The primary runner is a NixOS VM on the author's Mac with nested virtualization enabled by the hypervisor (vfkit `--nested`, macOS 15+ on M3 or later), **limited to one job at a time** because the VM also hosts the forge. A NixOS laptop with native KVM becomes a secondary `kvm` runner later. A TCG-only Linux builder is rejected as too slow. If nested virtualization disappoints, the `nixosTest`s are run by hand until the laptop exists.

v0 validation order: `nixosTest` with simulated NAT first, the real network second.

## Consequences

- The full `nix flake check` is green only on Linux with KVM; locally on macOS it is partial by construction, documented.
- Every milestone's acceptance criteria name the tier that proves them.
