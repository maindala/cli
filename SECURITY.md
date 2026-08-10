# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in the `maindala` CLI, please report it
privately rather than opening a public issue.

**Contact:** it@maindala.com

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a minimal proof-of-concept.
- The package version(s) affected (`maindala --version`).

We will acknowledge your report within **3 business days** and aim to provide an initial
assessment (confirmed / not applicable / needs more information) within **10 business days**.
If confirmed, we will work with you on a disclosure timeline and credit you in the release
notes unless you prefer to remain anonymous.

Please do not publicly disclose the issue until a fix has been released.

## Supported versions

This package follows semantic versioning. Only the latest published version receives security
fixes.

| Version | Supported |
|---|---|
| latest | ✅ |
| older  | ❌ |

## Scope

This CLI talks to the mAIndala catalog API (`https://api.maindala.com` by default, overridable
via `MAINDALA_API_KEY`/`MAINDALA_CATALOG_URL`) and, for `maindala run`, to a local Docker daemon
running the public `agent-runtime` image. A vulnerability report about the mAIndala-hosted
platform itself (as opposed to this CLI's own code) should also go to it@maindala.com — we will
route it internally.
