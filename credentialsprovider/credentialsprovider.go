// Package credentialsprovider implements MCP tool-level PAT/API-key
// collection ("Leg 2b"): structurally parallel to oauthprovider, but the
// "external redirect" is instead a form hosted by the MCP server ITSELF,
// never a third party's domain.
//
// This is a deliberate spec-compliance choice, not an implementation
// detail: the MCP spec says servers must not collect sensitive
// information via JSON-schema elicitation forms. So PAT/API-key
// collection happens via URL-mode elicitation to a self-hosted page —
// the secret never passes through the MCP JSON-RPC channel or the AI
// assistant at all. See ARCHITECTURE.md for the full rationale. This
// boundary must be preserved: never collect a secret through a
// JSON-schema form elicitation, only through a URL redirect to a page
// this server itself controls.
//
// Mirrors Python mcp-authkit's mcpauthkit.providers.credentials_provider
// module.
package credentialsprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/masterela/mcp-authkit-go/middleware"
	"github.com/masterela/mcp-authkit-go/store"
)

// FieldType is the HTML input type rendered for a Variable.
type FieldType string

// Supported form field types, rendered as the corresponding HTML input
// type (FieldTextarea renders as a <textarea> instead of <input>).
const (
	FieldText     FieldType = "text"
	FieldPassword FieldType = "password"
	FieldURL      FieldType = "url"
	FieldTextarea FieldType = "textarea"
)

// Variable describes one field of the credentials form.
type Variable struct {
	Label    string
	Type     FieldType
	Hint     string
	Required bool // defaults to true if the Variable is constructed via NewVariable
}

// NewVariable is a convenience constructor defaulting Required to true,
// matching the Python original's VariableDef default.
func NewVariable(label string, fieldType FieldType) Variable {
	return Variable{Label: label, Type: fieldType, Required: true}
}

const defaultTokenTimeout = 300 * time.Second // matches the Python original's default

// Options configures [New].
type Options struct {
	Name          string
	Variables     map[string]Variable
	ServerBaseURL string
	CredsStore    store.TokenStore   // optional; if nil, resolved via store.CreateStores(namespace=Name)
	PendingStore  store.PendingStore // optional; same fallback as CredsStore
	Doc           string             // optional Markdown how-to guide shown on the entry page
	TokenTimeout  time.Duration      // optional, default 300s
}

// Provider gates individual MCP tool calls behind a self-hosted
// credentials-entry form, presented via URL-mode elicitation.
type Provider struct {
	name          string
	variables     map[string]Variable
	serverBaseURL string
	credsStore    store.TokenStore
	pendingStore  store.PendingStore
	doc           string
	tokenTimeout  time.Duration

	entryPath  string
	submitPath string

	mu       sync.Mutex
	sessions map[string]*mcp.ServerSession
}

// New constructs a Provider. If CredsStore/PendingStore are nil, they
// are resolved via store.CreateStores(namespace=Name).
func New(opts Options) (*Provider, error) {
	if opts.TokenTimeout == 0 {
		opts.TokenTimeout = defaultTokenTimeout
	}
	credsStore, pendingStore := opts.CredsStore, opts.PendingStore
	if credsStore == nil || pendingStore == nil {
		ts, ps, err := store.CreateStores(store.FactoryOptions{Namespace: opts.Name})
		if err != nil {
			return nil, fmt.Errorf("credentialsprovider: creating default stores: %w", err)
		}
		if credsStore == nil {
			credsStore = ts
		}
		if pendingStore == nil {
			pendingStore = ps
		}
	}

	return &Provider{
		name:          opts.Name,
		variables:     opts.Variables,
		serverBaseURL: opts.ServerBaseURL,
		credsStore:    credsStore,
		pendingStore:  pendingStore,
		doc:           opts.Doc,
		tokenTimeout:  opts.TokenTimeout,
		entryPath:     fmt.Sprintf("/credentials/%s/entry", opts.Name),
		submitPath:    fmt.Sprintf("/credentials/%s/submit", opts.Name),
		sessions:      make(map[string]*mcp.ServerSession),
	}, nil
}

// OpenPaths returns the paths this Provider's routes live at, for
// inclusion in the Leg-1 middleware's OpenPaths — the entry/submit pages
// must be reachable by the user's browser without a bearer token (the
// human filling in the form is not necessarily the same principal as an
// MCP session's bearer token, and the form itself carries its own
// single-use, short-TTL token in its URL for authorization).
func (p *Provider) OpenPaths() []string {
	return []string{p.entryPath, p.submitPath}
}

// InvalidateCredentials deletes the stored credentials for sub.
func (p *Provider) InvalidateCredentials(ctx context.Context, sub string) error {
	return p.credsStore.Delete(ctx, sub)
}

func generateID(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var errPromptDeclined = errors.New("credentialsprovider: user declined the credentials prompt")

// RequireCredentials returns middleware that ensures credentials are
// available for the calling user before next runs — mirrors Python's
// require_credentials decorator. If failFast is true, missing
// credentials immediately return mcp.URLElicitationRequiredError instead
// of blocking.
func (p *Provider) RequireCredentials(failFast bool) func(next mcp.ToolHandler) mcp.ToolHandler {
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			user, ok := middleware.UserFromContext(ctx)
			if !ok {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "credentialsprovider: no authenticated user in context"}},
					IsError: true,
				}, nil
			}
			sub := user.Sub

			creds, err := p.credsStore.Get(ctx, sub)
			if err != nil {
				return nil, fmt.Errorf("credentialsprovider: checking existing credentials: %w", err)
			}
			if creds != nil {
				return next(withCredentials(ctx, creds), req)
			}

			if failFast {
				return nil, p.buildFailFastError(sub)
			}

			creds, err = p.ensureCredentialsBlocking(ctx, req.Session, sub)
			if err != nil {
				return nil, err
			}
			if creds == nil {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s credentials were not provided", p.name)}},
					IsError: true,
				}, nil
			}
			return next(withCredentials(ctx, creds), req)
		}
	}
}

func (p *Provider) buildFailFastError(sub string) error {
	entryToken := generateID(32)
	elicitationID := generateID(16)
	entryURL := p.serverBaseURL + p.entryPath + "?t=" + entryToken
	_ = p.pendingStore.Create(context.Background(), entryToken, map[string]any{"sub": sub}, int(p.tokenTimeout.Seconds()))

	return mcp.URLElicitationRequiredError([]*mcp.ElicitParams{
		{
			Mode:          "url",
			Message:       fmt.Sprintf("Provide %s credentials to continue", p.name),
			URL:           entryURL,
			ElicitationID: elicitationID,
		},
	})
}

func (p *Provider) ensureCredentialsBlocking(ctx context.Context, session *mcp.ServerSession, sub string) (map[string]any, error) {
	entryToken := generateID(32)
	elicitationID := generateID(16)
	entryURL := p.serverBaseURL + p.entryPath + "?t=" + entryToken

	if err := p.pendingStore.Create(ctx, entryToken, map[string]any{"sub": sub}, int(p.tokenTimeout.Seconds())); err != nil {
		return nil, fmt.Errorf("credentialsprovider: creating pending entry: %w", err)
	}
	p.mu.Lock()
	p.sessions[entryToken] = session
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.sessions, entryToken)
		p.mu.Unlock()
	}()

	result, err := session.Elicit(ctx, &mcp.ElicitParams{
		Mode:          "url",
		Message:       fmt.Sprintf("Provide %s credentials to continue", p.name),
		URL:           entryURL,
		ElicitationID: elicitationID,
	})
	if err != nil {
		return nil, fmt.Errorf("credentialsprovider: elicitation request failed: %w", err)
	}
	if result.Action != "accept" {
		_, _ = p.pendingStore.Pop(ctx, entryToken)
		return nil, errPromptDeclined
	}

	signal, err := p.pendingStore.WaitForResult(ctx, entryToken, p.tokenTimeout.Seconds())
	if err != nil {
		return nil, fmt.Errorf("credentialsprovider: waiting for submission: %w", err)
	}
	if signal == nil {
		return nil, nil // timed out
	}

	return p.credsStore.Get(ctx, sub)
}

// HandleEntry serves the self-hosted credentials-entry HTML form —
// register at OpenPaths()[0] ("GET /credentials/{name}/entry").
func (p *Provider) HandleEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entryToken := r.URL.Query().Get("t")
	if entryToken == "" {
		writeStatusPage(w, http.StatusBadRequest, "Error", "Missing entry token")
		return
	}

	pending, err := p.pendingStore.Get(ctx, entryToken)
	if err != nil || pending == nil {
		writeStatusPage(w, http.StatusBadRequest, "Error", "This link has expired or is invalid — please retry from your MCP client.")
		return
	}

	writeEntryForm(w, p.name, p.submitPath+"?t="+url.QueryEscape(entryToken), p.variables, p.doc)
}

// HandleSubmit processes the credentials-entry form POST — register at
// OpenPaths()[1] ("POST /credentials/{name}/submit").
func (p *Provider) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	entryToken := r.URL.Query().Get("t")
	if entryToken == "" {
		writeStatusPage(w, http.StatusBadRequest, "Error", "Missing entry token")
		return
	}

	// Atomically pop so a duplicate submit (e.g. double-click, or a
	// replayed request) is rejected rather than silently overwriting an
	// already-completed flow.
	pending, err := p.pendingStore.Pop(ctx, entryToken)
	if err != nil || pending == nil {
		writeStatusPage(w, http.StatusBadRequest, "Error", "This link has expired, is invalid, or was already used.")
		return
	}
	sub, _ := pending["sub"].(string)

	if err := r.ParseForm(); err != nil {
		writeStatusPage(w, http.StatusBadRequest, "Error", "Invalid form submission")
		return
	}

	collected := make(map[string]any, len(p.variables))
	for name, v := range p.variables {
		value := r.PostForm.Get(name)
		if v.Required && strings.TrimSpace(value) == "" {
			writeStatusPage(w, http.StatusBadRequest, "Error", fmt.Sprintf("Field %q is required", v.Label))
			return
		}
		collected[name] = value
	}

	if err := p.credsStore.Set(ctx, sub, collected); err != nil {
		writeStatusPage(w, http.StatusInternalServerError, "Error", "Storing credentials failed")
		return
	}

	elicitSent := false // this Go port does not implement the completion notification (see ARCHITECTURE.md)
	_ = p.pendingStore.SetResult(ctx, entryToken, map[string]any{"sub": sub, "_elicit_sent": elicitSent}, 120)

	writeStatusPage(w, http.StatusOK, "Success",
		fmt.Sprintf("Your %s credentials were saved. Your credentials are stored securely on the MCP server and are never exposed to the AI assistant. You can close this window and return to your MCP client.", p.name))
}

func writeEntryForm(w http.ResponseWriter, name, submitURL string, variables map[string]Variable, doc string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var b strings.Builder
	fmt.Fprintf(&b, "<!DOCTYPE html><html><head><title>%s credentials</title></head><body>", html.EscapeString(name))
	fmt.Fprintf(&b, "<h1>%s credentials</h1>", html.EscapeString(name))
	b.WriteString("<p>Your credentials are stored securely on the MCP server and are never exposed to the AI assistant.</p>")
	if doc != "" {
		fmt.Fprintf(&b, "<pre>%s</pre>", html.EscapeString(doc))
	}
	fmt.Fprintf(&b, `<form method="POST" action="%s">`, html.EscapeString(submitURL))
	for fieldName, v := range variables {
		inputType := "text"
		switch v.Type {
		case FieldPassword:
			inputType = "password"
		case FieldURL:
			inputType = "url"
		}
		fmt.Fprintf(&b, "<label>%s</label>", html.EscapeString(v.Label))
		if v.Type == FieldTextarea {
			fmt.Fprintf(&b, `<textarea name="%s" autocomplete="off"%s></textarea>`,
				html.EscapeString(fieldName), requiredAttr(v.Required))
		} else {
			fmt.Fprintf(&b, `<input type="%s" name="%s" autocomplete="off"%s>`,
				inputType, html.EscapeString(fieldName), requiredAttr(v.Required))
		}
		if v.Hint != "" {
			fmt.Fprintf(&b, "<small>%s</small>", html.EscapeString(v.Hint))
		}
	}
	b.WriteString(`<button type="submit">Save</button></form></body></html>`)

	w.Write([]byte(b.String())) //nolint:errcheck // best-effort write to an already-committed response
}

func requiredAttr(required bool) string {
	if required {
		return " required"
	}
	return ""
}

// writeStatusPage renders a minimal, self-contained HTML status page —
// this Go port intentionally does not replicate the Python original's
// styled Jinja2 templates; the user-facing content matches, presentation
// is plain.
func writeStatusPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>",
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(message))
}

type credentialsContextKey struct{}

func withCredentials(ctx context.Context, creds map[string]any) context.Context {
	return context.WithValue(ctx, credentialsContextKey{}, creds)
}

// CredentialsFromContext returns the credentials RequireCredentials
// resolved for the current tool call, for use inside the wrapped handler.
func CredentialsFromContext(ctx context.Context) (map[string]any, bool) {
	c, ok := ctx.Value(credentialsContextKey{}).(map[string]any)
	return c, ok
}
