---
title: DS003-main-behavior
summary: Defines login, session-based plugin access, and host registration.
---

## Introduction

Gatekeeper connects browser authentication to host-owned plugins.

## Core Content

### Main Behavior Components

| Name | Explanation |
| --- | --- |
| Account login | HTTP handlers use account plugins to validate supported credentials and establish sessions. |
| Protected plugin access | Proxy middleware separates explicit public calls from session-checked plugin calls. |
| Host registration | The initializer attaches routes and registers the API used by its plugins. |

### Account login

A browser submits an email code, passkey response, or TOTP value to the relevant route beneath `AUTH_API_PREFIX`. The handler validates the input and calls [UserLogin](wiki.html#definition-userlogin). A successful result supplies session information and authentication cookies. Login strategy and persistence contracts govern each method; header screening does not prove identity.

### Protected plugin access

A caller invokes `/proxy/*`. The middleware accepts explicitly public methods and the configured trusted internal-token path without ordinary session lookup. Other calls require a nonblocked user and a valid [session](wiki.html#definition-session). Failure produces an unauthorized response rather than forwarding the protected operation.

### Host registration

The integrating server invokes the exported initializer. Gatekeeper registers authentication routes, selects storage under the host root, and schedules registration of the [serverless API](wiki.html#definition-serverless-api). The host supplies the actual server and plugin environment.
