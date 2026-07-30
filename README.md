# `libre-ai-contract-types`

Disposable Rust projections and strict runtime validators for the canonical JSON Schemas in
`contracts/schemas/`.

The build script embeds all canonical schemas and generates Rust types with Typify. It dereferences
local schema references and removes validation-only conditionals unsupported by static Rust types.
Those projections are conveniences only: every untrusted or cross-module value must pass the
runtime JSON Schema validator.

The runtime registry is self-contained and performs no HTTP or filesystem schema retrieval.
Validation issues contain paths and keywords only, never rejected values.

## État du projet

<!-- libre-ai:project-status:begin -->
<!-- Section générée depuis project.v1.yaml — ne pas éditer à la main. -->

- Situation actuelle : Née verte en γ 3.4 (ex crates/contract-types) ; première git-dep Cargo intra-org prouvée avec artifacts.
- Maturité : usable
- Exposition : usable-verifiable
- Confiance : medium
- Preuves vérifiées le : 2026-07-30
- Avancement : 50 % du périmètre actuellement déclaré

<!-- libre-ai:project-status:end -->

La fiche [`project.v1.yaml`](./project.v1.yaml) est l'autorité de l'état du projet ; cette section en est générée et le gate de flotte échoue si elles divergent.
