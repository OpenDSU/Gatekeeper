---
title: DS001-coding-style
summary: Defines the existing CommonJS layout and host-dependent verification boundaries.
---

## Introduction

The implementation uses CommonJS modules.

## Core Content

Preserve the existing `.js` CommonJS interface. `index.js` registers the extension; `handlers/` adapts HTTP requests; `middlewares/` checks request and session conditions; `plugins/` owns account and persistence operations; `utils/` holds shared functions. Do not infer a repository-wide runtime migration from documentation conventions.

The package declares no test script. Existing test files depend on a running host or plugin environment and contain legacy interface assumptions. Documentation checks do not establish authentication correctness. Installation hooks clone external repositories, so their side effects and selected revisions belong to the host integration decision.
