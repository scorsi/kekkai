# ADR 0017 — Identity keys and key storage

Status: Accepted — 2026-10-13

Amended by [0033](0033-the-cli-in-rust.md) — 2026-10-24: the CLI is in Rust and calls `kekkai-core`'s key code; the shared keygen vectors are checked by the core's and the CLI's Rust tests, no longer by Go.

Amended by [0034](0034-certificates-groups-expiry-and-revocation.md) — 2026-10-29: in v1 a CA's Ed25519 key signs node certificates. It is kept offline, encrypted at rest with `age` to the operator's identity only, never to a host key. `kekkai ca keygen` writes the new key (the 32-byte RFC 8032 seed, key text form) to stdout only, to be piped into `age -e`, and its public key to stderr; `kekkai cert sign` and `kekkai ca pubkey` (which prints the public key again) read it on stdin from `age -d`. The CLI never encrypts, decrypts or stores it, so no `age` code enters kekkai. Node keys are unchanged.

## Context

Identity in v0 is a static key per node, listed in configuration. Hosts include an impermanent VM (root on tmpfs) and a headless Mac whose `/var/run` is on disk. Certificates come in v1.

## Options considered

- One Ed25519 key per node converted to X25519 for the handshake: a single key pair on disk, but a birational conversion reviewers must be convinced of.
- One X25519 key per node; signatures are only ever made by a CA (v1).

## Decision

- **One X25519 key per node**, used only in the handshake (0007). Nodes never sign anything in v0; in v1 the CA's Ed25519 key signs the node's X25519 key inside a certificate (Nebula's model). Lighthouse and relay each have their own X25519 key.
- **Life cycle**: `kekkai keygen` on the operator's machine, private key stored in the deployment's sops secrets, public key in clear in the shared peer list. sops-nix places the key at `/run/secrets/…`, owned by the service's static user (0018), mode 0400. The daemons hold **no persistent state**, so impermanence needs nothing persisted for kekkai.
- **Key at rest, platform facts**: on Linux `/run` is a tmpfs, so the decrypted key never touches the disk; the sops age key that unlocks it is on disk. On macOS `/run` is `/private/var/run`, **on disk**: the decrypted key is written to disk at every boot. On a host without full-disk encryption the key is therefore readable by anyone with the disk. This is an **accepted risk in v0**; which hosts are concerned is recorded in the private deployment repository (0025).
- **Mitigation path, not implemented**: keep the key encrypted at rest and unwrap it at service start; on macOS through the Secure Enclave (it does not do X25519, so a P-256 key wraps the X25519 key), on Linux through TPM2 and `systemd-creds` where a TPM exists. This protects against theft or copy of the disk, not against an attacker on the running machine.
- **Design constraint now**: the core receives the private key as an opaque `StaticKey` value loaded by the IO layer, never a file path, so that a hardware-backed unwrap can provide it later without touching the core.

## Consequences

- Rotating a node's key is a redeploy (0008).
- `kekkai keygen` vectors are shared between Go and Rust (0015).
