# Gatekeeper

## Scope

Gatekeeper is a CommonJS extension for an OpenDSU-compatible host server. It registers account-login routes and plugin-session middleware. The host owns the HTTP listener and plugin environment.

## Mandatory Reading Order

Read `docs/index.html`, `docs/specs/DS001-coding-style.md`, and `docs/specs/matrix.md`. Use `docs/specs/DS003-main-behavior.md` for the main workflows and `docs/operations.html` for integration boundaries. Inspect `index.js`, the affected handler or middleware, and its plugin before changing behavior.

## Current Skill Catalog

The package does not distribute an agent skill catalog.

## Repository Rules

Keep documentation in English and align it with the checked-out implementation. Preserve the CommonJS public interface, host integration, and plugin ownership. Keep secrets and real authentication values out of source, documentation, and test output. Preserve concurrent changes and the configured human Git identity; add no tool attribution to commits.

## Runtime Defaults

The exported initializer receives the host server. `AUTH_API_PREFIX` is captured when the entry module loads. The host supplies OpenDSU and `$$` facilities. Do not invent a standalone start command or package test script: neither is declared. Installation hooks clone dependencies and must be inspected before execution. Existing tests require a host or plugin environment and include legacy route assumptions.

## Key Paths

`index.js` registers routes. `handlers/auth.js` adapts HTTP requests. `middlewares/` checks headers and proxy sessions. `plugins/` owns account operations, login strategies, and persistence. `docs/wiki.html` defines project terminology; `docs/specs/` records the contracts.
