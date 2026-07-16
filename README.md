# `libre-ai-contract-types`

Disposable Rust projections and strict runtime validators for the canonical JSON Schemas in
`contracts/schemas/`.

The build script embeds all canonical schemas and generates Rust types with Typify. It dereferences
local schema references and removes validation-only conditionals unsupported by static Rust types.
Those projections are conveniences only: every untrusted or cross-module value must pass the
runtime JSON Schema validator.

The runtime registry is self-contained and performs no HTTP or filesystem schema retrieval.
Validation issues contain paths and keywords only, never rejected values.
