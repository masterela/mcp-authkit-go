// Package oauthprovider implements MCP tool-level third-party OAuth
// gating ("Leg 2a"): a redirect-based OAuth 2.0 flow that a specific
// tool call can require before proceeding, using MCP's URL-mode
// elicitation to present the authorization URL to the human.
//
// This mirrors Python mcp-authkit's mcpauthkit.providers.oauth_provider
// module. See ARCHITECTURE.md for the cross-instance signal protocol
// (the OAuth callback may land on a different server replica than the
// one that started the flow) implemented via the store package.
package oauthprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/masterela/mcp-authkit-go/middleware"
	"github.com/masterela/mcp-authkit-go/store"
)

// ExchangeFunc exchanges an authorization code for a token, or refreshes
// an existing token (when called by RefreshTokenFn). Returns the raw
// token data — a map that must contain at least "access_token", and
// optionally "refresh_token" and "expires_in" (a number of seconds).
type ExchangeFunc func(ctx context.Context, code string) (map[string]any, error)

// RefreshTokenFunc refreshes an existing token given its refresh token.
// Same return shape as ExchangeFunc.
type RefreshTokenFunc func(ctx context.Context, refreshToken string) (map[string]any, error)

const defaultTokenTimeout = 120 * time.Second

// Provider gates individual MCP tool calls behind a third-party OAuth
// 2.0 flow, presenting the authorization URL via URL-mode elicitation
// and blocking the tool call (or, in fail-fast mode, returning
// immediately with a structured retry-later error) until the user
// completes it.
type Provider struct {
	name           string
	buildAuthURL   func(state, redirectURI string) string
	exchangeCode   ExchangeFunc
	redirectURI    string
	callbackPath   string
	tokenStore     store.TokenStore
	pendingStore   store.PendingStore
	refreshTokenFn RefreshTokenFunc
	tokenTimeout   time.Duration
	httpClient     *http.Client

	mu       sync.Mutex
	sessions map[string]*mcp.ServerSession // OAuth "state" -> the session that started the flow, for callback wiring if ever needed
}

// StandardOAuth2Options configures [FromStandardOAuth2].
type StandardOAuth2Options struct {
	Name             string
	AuthorizationURL string
	TokenURL         string
	ClientID         string
	ClientSecret     string
	Scope            string
	RedirectURI      string
	TokenStore       store.TokenStore   // optional; if nil, resolved via store.CreateStores(namespace=Name)
	PendingStore     store.PendingStore // optional; same fallback as TokenStore
	RefreshTokenFn   RefreshTokenFunc   // optional
	TokenTimeout     time.Duration      // optional, default 120s
	HTTPClient       *http.Client       // optional, default http.DefaultClient
}

// FromStandardOAuth2 builds a Provider for a standard OAuth 2.0
// authorization-code flow, mirroring Python mcp-authkit's
// OAuthProvider.from_standard_oauth2 classmethod: constructs the
// authorization-URL builder and code-exchange function as closures over
// the given endpoints/credentials, so callers don't need to hand-write
// either for the common case.
func FromStandardOAuth2(opts StandardOAuth2Options) (*Provider, error) {
	if opts.TokenTimeout == 0 {
		opts.TokenTimeout = defaultTokenTimeout
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}

	buildAuthURL := func(state, redirectURI string) string {
		q := url.Values{
			"client_id":     {opts.ClientID},
			"redirect_uri":  {redirectURI},
			"response_type": {"code"},
			"scope":         {opts.Scope},
			"state":         {state},
		}
		return opts.AuthorizationURL + "?" + q.Encode()
	}

	exchangeCode := func(ctx context.Context, code string) (map[string]any, error) {
		form := url.Values{
			"client_id":     {opts.ClientID},
			"client_secret": {opts.ClientSecret},
			"code":          {code},
			"redirect_uri":  {opts.RedirectURI},
			"grant_type":    {"authorization_code"},
		}
		return doTokenRequest(ctx, opts.HTTPClient, opts.TokenURL, form)
	}

	var refreshFn RefreshTokenFunc
	if opts.RefreshTokenFn != nil {
		refreshFn = opts.RefreshTokenFn
	} else {
		refreshFn = func(ctx context.Context, refreshToken string) (map[string]any, error) {
			form := url.Values{
				"client_id":     {opts.ClientID},
				"client_secret": {opts.ClientSecret},
				"refresh_token": {refreshToken},
				"grant_type":    {"refresh_token"},
			}
			return doTokenRequest(ctx, opts.HTTPClient, opts.TokenURL, form)
		}
	}

	return New(Options{
		Name:           opts.Name,
		BuildAuthURL:   buildAuthURL,
		ExchangeCode:   exchangeCode,
		RedirectURI:    opts.RedirectURI,
		TokenStore:     opts.TokenStore,
		PendingStore:   opts.PendingStore,
		RefreshTokenFn: refreshFn,
		TokenTimeout:   opts.TokenTimeout,
		HTTPClient:     opts.HTTPClient,
	})
}

func doTokenRequest(ctx context.Context, client *http.Client, tokenURL string, form url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauthprovider: token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauthprovider: token endpoint returned status %d", resp.StatusCode)
	}
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("oauthprovider: decoding token response: %w", err)
	}
	return data, nil
}

// Options configures [New] directly, for callers who don't use the
// standard-OAuth2 shape (e.g. a provider with a non-standard token
// exchange, matching Python's general OAuthProvider constructor rather
// than its from_standard_oauth2 convenience classmethod).
type Options struct {
	Name           string
	BuildAuthURL   func(state, redirectURI string) string
	ExchangeCode   ExchangeFunc
	RedirectURI    string
	TokenStore     store.TokenStore
	PendingStore   store.PendingStore
	RefreshTokenFn RefreshTokenFunc
	TokenTimeout   time.Duration
	HTTPClient     *http.Client
}

// New constructs a Provider. If TokenStore/PendingStore are nil, they
// are resolved via store.CreateStores(namespace=Name) — the same
// env-var-driven lazy resolution as the Python original.
func New(opts Options) (*Provider, error) {
	if opts.TokenTimeout == 0 {
		opts.TokenTimeout = defaultTokenTimeout
	}
	tokenStore, pendingStore := opts.TokenStore, opts.PendingStore
	if tokenStore == nil || pendingStore == nil {
		ts, ps, err := store.CreateStores(store.FactoryOptions{Namespace: opts.Name})
		if err != nil {
			return nil, fmt.Errorf("oauthprovider: creating default stores: %w", err)
		}
		if tokenStore == nil {
			tokenStore = ts
		}
		if pendingStore == nil {
			pendingStore = ps
		}
	}

	parsed, err := url.Parse(opts.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("oauthprovider: parsing redirect URI: %w", err)
	}

	return &Provider{
		name:           opts.Name,
		buildAuthURL:   opts.BuildAuthURL,
		exchangeCode:   opts.ExchangeCode,
		redirectURI:    opts.RedirectURI,
		callbackPath:   parsed.Path,
		tokenStore:     tokenStore,
		pendingStore:   pendingStore,
		refreshTokenFn: opts.RefreshTokenFn,
		tokenTimeout:   opts.TokenTimeout,
		httpClient:     opts.HTTPClient,
		sessions:       make(map[string]*mcp.ServerSession),
	}, nil
}

// CallbackPath is the URL path (extracted from RedirectURI) the caller
// must route to [Provider.HandleCallback] — e.g. via
// mux.HandleFunc("GET "+provider.CallbackPath(), provider.HandleCallback).
func (p *Provider) CallbackPath() string { return p.callbackPath }

// InvalidateToken deletes the stored token for sub, e.g. after the
// downstream API returns 401 for a token this Provider issued.
func (p *Provider) InvalidateToken(ctx context.Context, sub string) error {
	return p.tokenStore.Delete(ctx, sub)
}

func generateID(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var errPromptDeclined = errors.New("oauthprovider: user declined the authorization prompt")

// RequireToken returns middleware that ensures a valid third-party OAuth
// token is available for the calling user before next runs, mirroring
// Python's require_token decorator. If failFast is true, a missing token
// immediately returns mcp.URLElicitationRequiredError instead of
// blocking — the client is expected to retry the tool call later.
//
// tokenFromContext lets the wrapped handler retrieve the resolved token
// without changing its own signature — call it with the same ctx passed
// to next.
func (p *Provider) RequireToken(failFast bool) func(next mcp.ToolHandler) mcp.ToolHandler {
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			user, ok := middleware.UserFromContext(ctx)
			if !ok {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "oauthprovider: no authenticated user in context"}},
					IsError: true,
				}, nil
			}
			sub := user.Sub

			token, err := p.getOrRefreshToken(ctx, sub)
			if err != nil {
				return nil, fmt.Errorf("oauthprovider: checking existing token: %w", err)
			}
			if token != "" {
				return next(withToken(ctx, token), req)
			}

			if failFast {
				return nil, p.buildFailFastError(sub)
			}

			token, err = p.ensureTokenBlocking(ctx, req.Session, sub)
			if err != nil {
				return nil, err
			}
			if token == "" {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s authorization was not completed", p.name)}},
					IsError: true,
				}, nil
			}
			return next(withToken(ctx, token), req)
		}
	}
}

func (p *Provider) buildFailFastError(sub string) error {
	state := generateID(24)
	elicitationID := generateID(16)
	authURL := p.buildAuthURL(state, p.redirectURI)
	// The pending entry must exist before the client retries and the
	// callback can land — created here even in the fail-fast path so a
	// later retry (which does NOT re-enter this function) has a valid
	// state to look up. In practice, fail-fast callers are expected to
	// prompt the same tool call again after the user completes the
	// external flow, at which point getOrRefreshToken finds the token
	// the callback stored.
	_ = p.pendingStore.Create(context.Background(), state, map[string]any{"sub": sub}, int(p.tokenTimeout.Seconds())+60)

	return mcp.URLElicitationRequiredError([]*mcp.ElicitParams{
		{
			Mode:          "url",
			Message:       fmt.Sprintf("Authorize access to %s to continue", p.name),
			URL:           authURL,
			ElicitationID: elicitationID,
		},
	})
}

func (p *Provider) ensureTokenBlocking(ctx context.Context, session *mcp.ServerSession, sub string) (string, error) {
	state := generateID(24)
	elicitationID := generateID(16)
	authURL := p.buildAuthURL(state, p.redirectURI)

	if err := p.pendingStore.Create(ctx, state, map[string]any{"sub": sub}, int(p.tokenTimeout.Seconds())+60); err != nil {
		return "", fmt.Errorf("oauthprovider: creating pending entry: %w", err)
	}
	p.mu.Lock()
	p.sessions[state] = session
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.sessions, state)
		p.mu.Unlock()
	}()

	result, err := session.Elicit(ctx, &mcp.ElicitParams{
		Mode:          "url",
		Message:       fmt.Sprintf("Authorize access to %s to continue", p.name),
		URL:           authURL,
		ElicitationID: elicitationID,
	})
	if err != nil {
		return "", fmt.Errorf("oauthprovider: elicitation request failed: %w", err)
	}
	if result.Action != "accept" {
		_, _ = p.pendingStore.Pop(ctx, state)
		return "", errPromptDeclined
	}

	signal, err := p.pendingStore.WaitForResult(ctx, state, p.tokenTimeout.Seconds())
	if err != nil {
		return "", fmt.Errorf("oauthprovider: waiting for callback: %w", err)
	}
	if signal == nil {
		return "", nil // timed out — caller reports "not completed"
	}

	return p.getOrRefreshToken(ctx, sub)
}

func (p *Provider) getOrRefreshToken(ctx context.Context, sub string) (string, error) {
	tokenData, err := p.tokenStore.Get(ctx, sub)
	if err != nil {
		return "", err
	}
	if tokenData == nil {
		return "", nil
	}

	accessToken, _ := tokenData["access_token"].(string)
	expiresAt, hasExpiry := tokenData["expires_at"].(float64)
	const expiryBufferSeconds = 30
	if !hasExpiry || float64(time.Now().Unix())+expiryBufferSeconds < expiresAt {
		return accessToken, nil
	}

	// Token is expired or expiring soon — attempt a silent refresh.
	refreshToken, _ := tokenData["refresh_token"].(string)
	if refreshToken == "" || p.refreshTokenFn == nil {
		return "", nil
	}
	refreshed, err := p.refreshTokenFn(ctx, refreshToken)
	if err != nil {
		_ = p.tokenStore.Delete(ctx, sub) // stale entry, matching the Python original's _try_silent_refresh failure handling
		return "", nil
	}
	entry := normalizeTokenData(refreshed, time.Now())
	if entry["refresh_token"] == nil || entry["refresh_token"] == "" {
		entry["refresh_token"] = refreshToken // carry forward if the provider didn't issue a new one
	}
	if err := p.tokenStore.Set(ctx, sub, entry); err != nil {
		return "", err
	}
	newAccessToken, _ := entry["access_token"].(string)
	return newAccessToken, nil
}

// HandleCallback is the HTTP handler for the OAuth redirect callback —
// register it at CallbackPath(). Mirrors Python's OAuthProvider's
// registered callback route.
func (p *Provider) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	if errCode := q.Get("error"); errCode != "" {
		state := q.Get("state")
		if state != "" {
			_ = p.pendingStore.SetResult(ctx, state, map[string]any{"error": "oauth_error"}, 120)
		}
		writeCallbackPage(w, http.StatusOK, "Authorization failed", errCode+": "+q.Get("error_description"))
		return
	}

	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		writeCallbackPage(w, http.StatusBadRequest, "Authorization failed", "missing code or state parameter")
		return
	}

	pending, err := p.pendingStore.Pop(ctx, state)
	if err != nil || pending == nil {
		writeCallbackPage(w, http.StatusBadRequest, "Authorization failed", "unknown or expired authorization request")
		return
	}
	sub, _ := pending["sub"].(string)

	tokenData, err := p.exchangeCode(ctx, code)
	if err != nil {
		_ = p.pendingStore.SetResult(ctx, state, map[string]any{"error": "exchange_failed"}, 120)
		writeCallbackPage(w, http.StatusOK, "Authorization failed", "token exchange failed")
		return
	}

	entry := normalizeTokenData(tokenData, time.Now())
	if err := p.tokenStore.Set(ctx, sub, entry); err != nil {
		writeCallbackPage(w, http.StatusInternalServerError, "Authorization failed", "storing token failed")
		return
	}

	elicitSent := false // this Go port does not implement the completion notification (see ARCHITECTURE.md); always reports false, matching the "different instance" branch of the Python original
	_ = p.pendingStore.SetResult(ctx, state, map[string]any{"sub": sub, "_elicit_sent": elicitSent}, 120)

	writeCallbackPage(w, http.StatusOK, "Authorization successful", "You can close this window and return to your MCP client.")
}

func normalizeTokenData(raw map[string]any, now time.Time) map[string]any {
	entry := map[string]any{}
	if accessToken, ok := raw["access_token"]; ok {
		entry["access_token"] = accessToken
	}
	if refreshToken, ok := raw["refresh_token"]; ok {
		entry["refresh_token"] = refreshToken
	}
	entry["stored_at"] = now.Unix()
	if expiresIn, ok := toFloat(raw["expires_in"]); ok {
		entry["expires_at"] = float64(now.Unix()) + expiresIn
	}
	return entry
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// writeCallbackPage renders a minimal, self-contained HTML status page —
// this Go port intentionally does not replicate the Python original's
// styled Jinja2 templates (base.html + oauth_success/error.html); the
// user-facing content and messaging match, but presentation is a plain
// unstyled page. Revisit if a styled template matching the Python
// original's look is wanted later.
func writeCallbackPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html><html><head><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>",
		title, title, message)
}

type tokenContextKey struct{}

func withToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

// TokenFromContext returns the OAuth token RequireToken resolved for the
// current tool call, for use inside the wrapped handler.
func TokenFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tokenContextKey{}).(string)
	return t, ok
}
