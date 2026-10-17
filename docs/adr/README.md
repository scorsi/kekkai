# ADR — kekkai (結界)

Architecture decisions of the overlay. Format: status, context, options considered, decision, consequences. An ADR is not modified once accepted: it is superseded by a new one that references it.

Statuses: **Accepted** (decided on 2026-10-13 unless noted), **Proposed**, **Open**.

| No.  | Title                                                   | Status   |
| ---- | ------------------------------------------------------- | -------- |
| 0001 | Name, scope and goals                                   | Accepted |
| 0002 | Languages                                               | Accepted |
| 0003 | Cryptographic foundations and protocol specification    | Accepted |
| 0004 | Sans-IO core                                            | Accepted |
| 0005 | Components and roles                                    | Accepted |
| 0006 | Threat model                                            | Accepted |
| 0007 | Handshake: Noise IKpsk2, TLV payloads, identity trait   | Accepted |
| 0008 | Sessions, nonces and timers                             | Accepted |
| 0009 | Wire format and inner protocol                          | Accepted |
| 0010 | Overlay addressing and coexistence with Tailscale       | Accepted |
| 0011 | Per-peer inbound firewall                               | Accepted |
| 0012 | Lighthouse protocol                                     | Accepted |
| 0013 | NAT traversal, path selection and roaming               | Accepted |
| 0014 | Relay                                                   | Accepted |
| 0015 | Control API and CLI                                     | Accepted |
| 0016 | Configuration                                           | Accepted |
| 0017 | Identity keys and key storage                           | Accepted |
| 0018 | Platforms and service hardening                         | Accepted |
| 0019 | Observability                                           | Accepted |
| 0020 | Testing strategy                                        | Accepted |
| 0021 | Cryptographic review gates                              | Accepted |
| 0022 | CI and Nix integration                                  | Accepted |
| 0023 | Monorepo layout                                         | Accepted |
| 0024 | Versions, releases and compatibility                    | Accepted |
| 0025 | License and public documentation policy                 | Accepted |
| 0026 | Deploying over the overlay                              | Accepted |
| 0027 | Future work and the constraints it imposes on v0        | Accepted |
| 0028 | Non-cryptographic dependencies of kekkai-core           | Proposed |

Deployment-specific values (overlay prefixes, peers, public keys, which host carries which role, accepted host-level risks) are not recorded here: see 0025.
