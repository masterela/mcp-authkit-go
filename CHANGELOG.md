# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-07-22

### Added

- Initial Go port of [mcp-authkit](https://github.com/masterela/mcp-authkit).
- `jwtvalidator`: stateless OIDC/JWKS-based JWT verification (Leg 1 core).
- `middleware`: JWT auth middleware + OAuth/MCP well-known discovery endpoints (Leg 1).
- `store`: pluggable `TokenStore`/`PendingStore` abstraction with memory, file, and Redis backends, AES-256-GCM encryption at rest.
- `oauthprovider`: third-party OAuth 2.0 tool gating via URL-mode elicitation (Leg 2a).
- `credentialsprovider`: self-hosted PAT/API-key form tool gating via URL-mode elicitation (Leg 2b).

[0.1.0]: https://github.com/masterela/mcp-authkit-go/releases/tag/v0.1.0
