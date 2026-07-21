# TapChat hpke-rs manifest patch

This directory contains the four build-time packages used by TapChat from
`celabshq/hpke-rs` commit
`e1a4b12d3e630c713a89e97a2a91e4a597f3fc82`. The source is licensed under
MPL-2.0.

TapChat changes package manifests only:

- `libcrux-sha3` is pinned to `0.0.10`; the published `hpke-rs 0.6.1`
  package pinned `0.0.8`, while the recorded upstream commit pinned `0.0.9`.
- `hpke-rs-libcrux` uses the compatible fixed family: `libcrux-aead 0.0.9`,
  `ecdh 0.0.8`, `hkdf 0.0.8`, `kem 0.0.9`, and `traits 0.0.8`.
- The four packages retain their upstream internal path relationships because
  the recorded commit changed their shared provider API.
- Development-only dependencies and benchmark targets are removed because the
  local source is excluded from TapChat's workspace.

This removes the versions affected by RUSTSEC-2026-0207,
RUSTSEC-2026-0208, and RUSTSEC-2026-0212 from TapChat's active HPKE graph.
The Rust source files are unchanged from the recorded upstream commit. The
resolved provider graph contains the RUSTSEC-2026-0124-fixed
`libcrux-chacha20poly1305 0.0.9`.

Remove this directory and all four root `[patch.crates-io]` entries after an
upstream hpke-rs release adopts compatible fixed libcrux dependencies.
