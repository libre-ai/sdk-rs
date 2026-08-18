# sdk-rs Canonical Agent Rules

## Authority

Rust SDK projection (couche 4) of the Libre AI locked contracts: it lets
constellation crates consume contracts in Rust without manual copying,
producing types conformant to the authorities under a drift gate. The
`schemas/` directory is a verified projection of the contracts authority
(https://raw.githubusercontent.com/libre-ai/contracts/main/AGENTS.md),
pinned in `package.json`/`bun.lock`, embedded at compile time by
`build.rs`, byte-exact under `bun run check:schemas`, never hand-edited.
Fleet doctrine and the gate template live upstream:
https://raw.githubusercontent.com/libre-ai/governance/main/AGENTS.md

## Boundaries

- Contract shapes are canonical in `libre-ai/contracts`; a contract
  change here is a pin bump plus re-vendoring, never an edit.
- Current exposure and acceptance state live in this repository's own
  `project.v1.yaml`, aggregated by governance — never duplicated here.

## Quality gates

Run `bun run check`; for the Rust crate, `cargo test --locked
--all-features`. Never hide a red test.

## Agents

- Read actual state before editing.
- Stage files before running tree-walking gates.
- Security > quality > performance > completeness.
