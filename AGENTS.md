# sdk-rs Canonical Agent Rules

Rust SDK projection (couche 4) of the Libre AI locked contracts. The
`schemas/` directory is a **verified projection** of the `contracts`
authority at the revision pinned in `package.json`/`bun.lock` (I-05):
embedded at compile time by `build.rs`, byte-exact under
`bun run check:schemas`, never hand-edited, never canonical. A contract
change here is a pin bump plus re-vendoring (`--write`), never an edit.
The governance gate template is consumed as pinned reusable workflows and
a pinned tooling git-dep. Consumers install this crate as a sha-pinned
Cargo git-dep ([sources.allow-org] github = ["libre-ai"]).

The repository's tests are Rust and OWNED by the rust-quality CI job
(cargo test --locked after bun install); the bun chain deliberately does
not run them — « the chain is green » proves the gates, « rust-quality is
green » proves the tests (K4 SDKRS-02). Run `bun run check` and
`cargo test --locked` before pushing; never hide a red
test. Security > quality > performance > completeness.
