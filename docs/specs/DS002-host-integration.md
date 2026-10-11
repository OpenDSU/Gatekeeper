---
title: DS002-host-integration
summary: Defines configuration, routes, and boundaries supplied by the host.
---

## Introduction

Gatekeeper is initialized with a host server object.

## Core Content

The host must provide routing methods, `rootFolder`, `createServerlessAPI`, and `registerServerlessProcess`. `AUTH_API_PREFIX` must be established before the entry module is loaded. `SERVERLESS_STORAGE` and `SERVERLESS_ID` have initializer defaults; the initializer generates `SERVERLESS_AUTH_SECRET` when absent. Persistence uses the host external volume.

Browser-header screening is not authentication. The creation-rate-limit route list in `securityMiddleware.js` is empty; no route-level enforcement may be claimed from that code alone. The proxy middleware has explicit public-method and trusted-internal-token bypasses in addition to session checks.
