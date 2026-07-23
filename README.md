# mcp-authkit-go

[![CI](https://github.com/masterela/mcp-authkit-go/actions/workflows/ci.yml/badge.svg)](https://github.com/masterela/mcp-authkit-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/masterela/mcp-authkit-go.svg)](https://pkg.go.dev/github.com/masterela/mcp-authkit-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Go port of [mcp-authkit](https://github.com/masterela/mcp-authkit) — a pluggable authentication library for [MCP](https://modelcontextprotocol.io) servers built on the official [`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk).

It handles two independent authentication legs:

- **Leg 1 — session auth** — every MCP session is gated behind a standard OIDC provider (Keycloak, Okta, Entra ID, Auth0, …) using JWT bearer tokens. `middleware.New` validates tokens and `middleware.RegisterWellKnownRoutes` publishes the RFC 8414 / MCP-spec well-known endpoints so the MCP client drives the PKCE flow automatically.
- **Leg 2 — tool-level credentials** — individual tools can additionally require a third-party OAuth token (`oauthprovider.Provider`) or a PAT / API key (`credentialsprovider.Provider`), collected on demand via [MCP URL-mode elicitation](https://spec.modelcontextprotocol.io/specification/2025-11-25/client/elicitation/).

This port targets the pre-`2026-07-28` push-style elicitation model (`session.Elicit` blocking in-process) — the same model the [Python original](https://github.com/masterela/mcp-authkit) and the official [`github-mcp-server`](https://github.com/github/github-mcp-server) use today. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and known deviations from the Python original.

---

## Installation

```bash
go get github.com/masterela/mcp-authkit-go
```

---

## Quick start

### Step 1 — Add the JWT middleware (Leg 1)

```go
validator, err := jwtvalidator.New(ctx)
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
middleware.RegisterWellKnownRoutes(mux, middleware.WellKnownOptions{
    ServerBaseURL: serverBaseURL,
    IssuerURL:     issuerURL,
    ClientID:      clientID,
})

authMiddleware := middleware.New(middleware.Options{
    Validator:     validator,
    IssuerURL:     issuerURL,
    ServerBaseURL: serverBaseURL,
    OpenPaths:     []string{"/.well-known", "/health", "/register"},
})
mux.Handle("/mcp/", authMiddleware(mcpHandler))
```

### Step 2 — Gate a tool behind a third-party OAuth token (Leg 2a)

```go
provider, err := oauthprovider.FromStandardOAuth2(oauthprovider.StandardOAuth2Options{
    Name:             "github",
    AuthorizationURL: "https://github.com/login/oauth/authorize",
    TokenURL:         "https://github.com/login/oauth/access_token",
    ClientID:         os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret:     os.Getenv("GITHUB_CLIENT_SECRET"),
    Scope:            "read:user repo",
    RedirectURI:      serverBaseURL + "/github/callback",
})
mux.HandleFunc("GET "+provider.CallbackPath(), provider.HandleCallback)

listPRs := provider.RequireToken(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    token, _ := oauthprovider.TokenFromContext(ctx)
    // use token against the GitHub API
    return &mcp.CallToolResult{}, nil
})
```

### Step 3 — Gate a tool behind a PAT / API key form (Leg 2b)

```go
creds, err := credentialsprovider.New(credentialsprovider.Options{
    Name: "confluence",
    Variables: map[string]credentialsprovider.Variable{
        "pat": credentialsprovider.NewVariable("Personal Access Token", credentialsprovider.FieldPassword),
    },
    ServerBaseURL: serverBaseURL,
})
mux.HandleFunc("GET "+creds.OpenPaths()[0], creds.HandleEntry)
mux.HandleFunc("POST "+creds.OpenPaths()[1], creds.HandleSubmit)

listPages := creds.RequireCredentials(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    values, _ := credentialsprovider.CredentialsFromContext(ctx)
    pat := values["pat"]
    // use pat against the Confluence API
    return &mcp.CallToolResult{}, nil
})
```

---

## Storage backends

| Mode | Notes |
|---|---|
| `memory` (default) | In-process. Tokens lost on restart. Good for development. |
| `file` | AES-256-GCM-encrypted JSON files. Single-instance deployments. |
| `redis` | `go-redis/v9`. Multi-replica deployments. |

Select via the `TOKEN_STORAGE_MODE` env var (`memory` / `file` / `redis`). See [ARCHITECTURE.md](ARCHITECTURE.md) for why this port uses AES-256-GCM rather than the Python original's Fernet.

---

## Documentation

Full API reference: [pkg.go.dev/github.com/masterela/mcp-authkit-go](https://pkg.go.dev/github.com/masterela/mcp-authkit-go)

Architecture, the two-leg auth model, and known deviations from the Python original: [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Contributing

```bash
go build ./...
golangci-lint run ./...
go test ./... -race -cover
```
