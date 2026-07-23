package oauthprovider_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/middleware"
	"github.com/masterela/mcp-authkit-go/oauthprovider"
	"github.com/masterela/mcp-authkit-go/store"
)

var testImpl = &mcp.Implementation{Name: "test", Version: "v1.0.0"}

// connectedSession returns a real, connected *mcp.ServerSession backed
// by an in-memory transport, with the client side driven by
// elicitationHandler — mirrors the SDK's own elicitation_test.go setup.
// This is a real MCP session, not a mock, so Provider.RequireToken's
// call to session.Elicit exercises the actual SDK wire protocol.
func connectedSession(t *testing.T, elicitationHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ServerSession {
	t.Helper()
	ctx := context.Background()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	server := mcp.NewServer(testImpl, nil)
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(testImpl, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{
			Elicitation: &mcp.ElicitationCapabilities{URL: &mcp.URLElicitationCapabilities{}},
		},
		ElicitationHandler: elicitationHandler,
	})
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientSession.Close() })

	return serverSession
}

func newTestProvider(t *testing.T, exchange oauthprovider.ExchangeFunc) (*oauthprovider.Provider, store.TokenStore) {
	t.Helper()
	tokenStore := store.NewMemoryTokenStore()
	pendingStore := store.NewMemoryPendingStore()

	p, err := oauthprovider.New(oauthprovider.Options{
		Name: "test-provider",
		BuildAuthURL: func(state, redirectURI string) string {
			return "https://provider.example.com/authorize?state=" + state
		},
		ExchangeCode: exchange,
		RedirectURI:  "https://mcp.example.com/test-provider/callback",
		TokenStore:   tokenStore,
		PendingStore: pendingStore,
		TokenTimeout: 2 * time.Second,
	})
	require.NoError(t, err)
	return p, tokenStore
}

func contextWithUser(sub string) context.Context {
	return middleware.WithUser(context.Background(), middleware.User{Sub: sub})
}

func extractState(t *testing.T, elicitedURL string) string {
	t.Helper()
	parsed, err := url.Parse(elicitedURL)
	require.NoError(t, err)
	state := parsed.Query().Get("state")
	require.NotEmpty(t, state, "elicited URL must carry a state param: %s", elicitedURL)
	return state
}

func TestRequireToken_CachedValidToken_SkipsElicitation(t *testing.T) {
	ctx := context.Background()
	p, tokenStore := newTestProvider(t, nil)
	require.NoError(t, tokenStore.Set(ctx, "user-1", map[string]any{
		"access_token": "cached-token",
		"expires_at":   float64(time.Now().Add(time.Hour).Unix()),
	}))

	session := connectedSession(t, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		t.Fatal("elicitation should not be triggered when a valid cached token exists")
		return nil, nil
	})

	var gotToken string
	handler := p.RequireToken(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		gotToken, _ = oauthprovider.TokenFromContext(ctx)
		return &mcp.CallToolResult{}, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.NoError(t, err)
	require.Equal(t, "cached-token", gotToken)
}

func TestRequireToken_FailFast_ReturnsURLElicitationRequiredError(t *testing.T) {
	p, _ := newTestProvider(t, nil)

	handler := p.RequireToken(true)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called when no token is cached and failFast is true")
		return nil, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: nil})
	require.Error(t, err)

	var rpcErr *jsonrpc.Error
	require.True(t, errors.As(err, &rpcErr), "expected a *jsonrpc.Error, got %T: %v", err, err)
	require.EqualValues(t, mcp.CodeURLElicitationRequired, rpcErr.Code)
}

func TestRequireToken_BlockingFlow_CompletesViaCallback(t *testing.T) {
	exchangeCalled := false
	exchange := func(ctx context.Context, code string) (map[string]any, error) {
		exchangeCalled = true
		require.Equal(t, "auth-code-123", code)
		return map[string]any{"access_token": "fresh-token", "expires_in": 3600}, nil
	}
	p, _ := newTestProvider(t, exchange)

	elicitedURLCh := make(chan string, 1)
	session := connectedSession(t, func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		elicitedURLCh <- req.Params.URL
		return &mcp.ElicitResult{Action: "accept"}, nil
	})

	// Simulate the OAuth callback landing while the tool call is blocked
	// waiting on pendingStore.WaitForResult.
	go func() {
		elicitedURL := <-elicitedURLCh
		state := extractState(t, elicitedURL)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test-provider/callback?code=auth-code-123&state="+state, nil)
		p.HandleCallback(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}()

	var gotToken string
	handler := p.RequireToken(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		gotToken, _ = oauthprovider.TokenFromContext(ctx)
		return &mcp.CallToolResult{}, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.NoError(t, err)
	require.True(t, exchangeCalled)
	require.Equal(t, "fresh-token", gotToken)
}

func TestRequireToken_UserDeclines_ReturnsError(t *testing.T) {
	p, _ := newTestProvider(t, nil)

	session := connectedSession(t, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	handler := p.RequireToken(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called when the user declines")
		return nil, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.Error(t, err)
}

func TestRequireToken_TimesOutWithoutCallback(t *testing.T) {
	p, _ := newTestProvider(t, nil)

	session := connectedSession(t, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept"}, nil
	})

	handler := p.RequireToken(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called when the callback never arrives")
		return nil, nil
	})

	result, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestRequireToken_NoUserInContext_ReturnsErrorResult(t *testing.T) {
	p, _ := newTestProvider(t, nil)

	handler := p.RequireToken(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called without an authenticated user")
		return nil, nil
	})

	result, err := handler(context.Background(), &mcp.CallToolRequest{})
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestRequireToken_ExpiredTokenWithRefresh_UsesRefreshedToken(t *testing.T) {
	ctx := context.Background()
	tokenStore := store.NewMemoryTokenStore()
	require.NoError(t, tokenStore.Set(ctx, "user-1", map[string]any{
		"access_token":  "stale-token",
		"refresh_token": "refresh-me",
		"expires_at":    float64(time.Now().Add(-time.Hour).Unix()), // already expired
	}))

	p, err := oauthprovider.New(oauthprovider.Options{
		Name:         "test-provider",
		BuildAuthURL: func(state, redirectURI string) string { return "https://provider.example.com/authorize" },
		RedirectURI:  "https://mcp.example.com/test-provider/callback",
		TokenStore:   tokenStore,
		PendingStore: store.NewMemoryPendingStore(),
		RefreshTokenFn: func(ctx context.Context, refreshToken string) (map[string]any, error) {
			require.Equal(t, "refresh-me", refreshToken)
			return map[string]any{"access_token": "refreshed-token", "expires_in": 3600}, nil
		},
	})
	require.NoError(t, err)

	var gotToken string
	handler := p.RequireToken(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		gotToken, _ = oauthprovider.TokenFromContext(ctx)
		return &mcp.CallToolResult{}, nil
	})

	_, err = handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: nil})
	require.NoError(t, err)
	require.Equal(t, "refreshed-token", gotToken)
}
