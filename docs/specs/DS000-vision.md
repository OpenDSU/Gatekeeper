---
title: DS000-vision
summary: Defines Gatekeeper as a host-integrated account and session extension.
---

## Introduction

Gatekeeper supplies authentication workflows to an existing server.

## Core Content

The package must expose its server initializer and plugin-backed authentication routes. The host owns the listener, OpenDSU environment, routing implementation, and persistent storage locations. Gatekeeper must not be documented as a standalone server with an undeclared start command.
