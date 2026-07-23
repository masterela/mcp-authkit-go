# Architecture

This is a Go port of [mcp-authkit](https://github.com/masterela/mcp-authkit) (Python), targeting the official [`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk). It replicates the Python original's two-leg auth model and package boundaries as closely as Go idioms allow, and documents every deliberate deviation below rather than silently drifting from the design.

## Two-leg model

**Leg 1 — session auth** (`jwtvalidator` + `middleware`): every MCP session is gated behind a standard OIDC provider using JWT bearer tokens.

- `jwtvalidator.Validator` fetches and caches an issuer's OIDC discovery document and JWKS (via `jwx/v3`'s `jwk.Cache`), then verifies bearer tokens against the cached key set. A disallowed signing algorithm (notably `none`) is rejected before any verification is attempted, checked directly on the unverified header.
- `middleware.New` wraps an `http.Handler`: extracts the Bearer token, validates it via a `*jwtvalidator.Validator`, and — on success — places a fixed-shape `middleware.User` value into the request's `context.Context` (retrievable via `middleware.UserFromContext`). OPTIONS requests and any path matching a configured `OpenPaths` prefix bypass auth entirely.
- `middleware.RegisterWellKnownRoutes` publishes `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, and a `/register` Dynamic Client Registration façade — the endpoints an MCP client needs to discover how to authenticate and drive the PKCE flow automatically.

**Known historical bug, fixed here and regression-tested**: `oauth-protected-resource`'s `authorization_servers` field must list **this MCP server's own base URL**, not the upstream OIDC issuer. The Python original regressed this once (0.2.0) and reverted it (0.2.1) — `middleware/routes_test.go`'s `TestProtectedResourceMetadata_AuthorizationServersListsOwnBaseURL` exists specifically to catch a repeat of that mistake in this port.

**Leg 2a — third-party OAuth** (`oauthprovider`): a redirect-based OAuth 2.0 flow gating an individual tool call.

**Leg 2b — PAT/API-key collection** (`credentialsprovider`): structurally parallel to Leg 2a, but the "external redirect" is a form **hosted by the MCP server itself**, never a third party's domain.

This is a deliberate spec-compliance choice, not an implementation detail: the MCP spec's own `ElicitRequestURLParams` documentation states URL-mode elicitation is "for sensitive out-of-band interactions like OAuth flows, credential collection, or payment processing" — the implication being that **form-mode elicitation must never carry sensitive data**. `credentialsprovider` never collects a PAT/API-key through a JSON-schema elicitation form; it always redirects (via URL-mode elicitation) to a page this server itself controls, and the secret never passes through the MCP JSON-RPC channel or the AI assistant at all. The only use of form-mode elicitation anywhere in this library is a trivial boolean "I completed this" acknowledgment, used only as a fallback when a client doesn't support URL-mode elicitation at all (see "Fallback fully out of scope" below — this port does not implement even that fallback, but preserves the boundary the fallback itself respects).

## The blocking/fail-fast pattern

Both `oauthprovider.Provider.RequireToken` and `credentialsprovider.Provider.RequireCredentials` return `func(next mcp.ToolHandler) mcp.ToolHandler` — idiomatic Go middleware wrapping, chosen over trying to replicate Python's decorator syntax. Two modes:

- **Blocking** (`failFast=false`): calls `session.Elicit(ctx, &mcp.ElicitParams{Mode: "url", ...})`, which blocks in-process until the client responds. On accept, blocks further on a `store.PendingStore.WaitForResult` call until the out-of-band HTTP callback (OAuth) or form submission (credentials) signals completion, or a timeout elapses.
- **Fail-fast** (`failFast=true`): returns `mcp.URLElicitationRequiredError(...)` (JSON-RPC error code `-32042`) immediately instead of blocking. The client is expected to retry the same tool call later, after the user completes the flow out-of-band.

## Cross-instance signal protocol

A subtlety carried over faithfully from the Python original: the OAuth callback (or credentials form submission) might land on a **different server replica** than the one that started the flow and is blocked in `WaitForResult`. This is why `store.PendingStore` exists as its own interface, separate from `store.TokenStore` — it's a cross-process future-with-timeout, not just a cache:

1. The replica handling the tool call creates a pending entry (`PendingStore.Create`) keyed by a random `state`/entry-token, then calls `session.Elicit` and blocks on `PendingStore.WaitForResult(state, timeout)`.
2. The replica handling the callback/submission (possibly a *different* replica, since a load balancer has no reason to route it back to the same one) pops the pending entry (`PendingStore.Pop`), stores the resolved token/credentials, and calls `PendingStore.SetResult(state, ...)`.
3. Whichever replica is blocked in `WaitForResult` observes the result (via an in-process channel for `MemoryPendingStore`, or polling for `FilePendingStore`/`RedisPendingStore`) and returns.

This is why `Memory{Token,Pending}Store` is single-process-only (fine for local dev) while `File`/`Redis` backends are required for any real multi-replica deployment.

## Deliberate deviations from the Python original

### AES-256-GCM instead of Fernet

The Python original encrypts stored tokens/credentials at rest using [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256). Go has no well-maintained Fernet-compatible library (`fernet/fernet-go` is abandoned, last commit January 2024). This port uses **AES-256-GCM** via the standard library's `crypto/aes`/`crypto/cipher` instead — an equivalent authenticated-encryption primitive (confidentiality + integrity), just a different wire format. This is safe because **there is no cross-language token-portability requirement** between the Python, Go, and TypeScript ports — each language's encrypted values are only ever read back by that same language's store implementation.

### No completion notification (`notifications/elicitation/complete`)

The Python original calls `session.send_elicit_complete(elicitation_id)` after an out-of-band flow (OAuth callback or credentials submission) resolves, to explicitly notify the client the interaction finished — relevant specifically for the cross-instance case, where the replica that receives the callback isn't the one blocked in `Elicit`.

As of `modelcontextprotocol/go-sdk` v1.6.1, there is **no public API** to send this notification from application code: the underlying `handleNotify` function is package-private, and the only place `notifications/elicitation/complete` is actually sent is inside the SDK's own test suite. This was confirmed by reading the SDK source directly, not assumed.

**Resolution, verified against real-world precedent**: the official [`github-mcp-server`](https://github.com/github/github-mcp-server)'s own OAuth implementation (which also uses `modelcontextprotocol/go-sdk`) does **not** use a completion notification either — `session.Elicit` itself blocks in-process until the client responds, which is sufficient for GitHub's production use case. This port follows the same approach: `HandleCallback`/`HandleSubmit` always report `_elicit_sent: false` internally (matching the Python original's "different instance, no local session to notify" branch), and no completion notification is ever sent. If `go-sdk` adds a public API for this later, revisit — track this as a known gap, not a permanent design decision.

### No styled HTML templates

The Python original renders styled Jinja2 templates (`base.html` + per-outcome pages) for the OAuth callback and credentials entry/success/error pages, including a shared visual shell and Markdown rendering (via `marked.js`) for an optional how-to doc. This port renders minimal, unstyled HTML with matching user-facing copy (including the exact "Your credentials are stored securely on the MCP server and are never exposed to the AI assistant" messaging) but no shared visual design. This is a presentation-only gap, not a functional one — revisit if a styled look matching the Python original is wanted.

### Fallback-to-form-mode elicitation not implemented

The Python original falls back to form-mode elicitation (a trivial `{completed: bool}` schema) when a client's declared capabilities don't include URL-mode elicitation at all, so the raw authorization/entry URL can be shown as plain text for the user to open manually. This port assumes URL-mode elicitation support and does not implement that fallback. Track as a known gap if a client without URL-mode support needs to be supported.

## Component map

```
jwtvalidator  →  middleware  →  (your MCP HTTP handler)
                     ↑
                     | reads middleware.User via UserFromContext
                     |
oauthprovider ───────┤
credentialsprovider ─┘
                     ↓
                   store  (TokenStore + PendingStore: memory | file | redis)
```

`oauthprovider` and `credentialsprovider` depend on `middleware` (to read the authenticated user) and `store` (for token/pending persistence), but not on each other. `jwtvalidator` has no dependency on any other package in this module.
