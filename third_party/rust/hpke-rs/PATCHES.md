# TapChat hpke-rs manifest patch

This directory contains the three build-time packages used by TapChat from
`celabshq/hpke-rs` commit
`e1a4b12d3e630c713a89e97a2a91e4a597f3fc82`. The source is licensed under
MPL-2.0.

TapChat changes package manifests only:

- `libcrux-sha3` is pinned to `0.0.10`; the published `hpke-rs 0.6.1`
  package pinned `0.0.8`, while the recorded upstream commit pinned `0.0.9`.
- The optional libcrux backend (`hpke-rs-libcrux`, the `libcrux` feature and
  the features that only forwarded to it) is removed. TapChat never enabled it,
  and Cargo locks optional dependencies, so its `libcrux-kem 0.0.9`
  (RUSTSEC-2026-0330, RUSTSEC-2026-0331) sat in Cargo.lock. The one
  `cfg(feature = "libcrux")` in `src/lib.rs` is declared as an expected cfg.
- The three packages retain their upstream internal path relationships because
  the recorded commit changed their shared provider API.
- Development-only dependencies and benchmark targets are removed because the
  local source is excluded from TapChat's workspace.

This removes the versions affected by RUSTSEC-2026-0207,
RUSTSEC-2026-0208, RUSTSEC-2026-0212, RUSTSEC-2026-0330 and RUSTSEC-2026-0331
from Cargo.lock. The Rust source files are unchanged from the recorded upstream
commit.

Remove this directory and all three root `[patch.crates-io]` entries after an
upstream hpke-rs release adopts compatible fixed libcrux dependencies.
