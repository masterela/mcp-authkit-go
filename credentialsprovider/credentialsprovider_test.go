package credentialsprovider_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/masterela/mcp-authkit-go/credentialsprovider"
	"github.com/masterela/mcp-authkit-go/middleware"
	"github.com/masterela/mcp-authkit-go/store"
)

var testImpl = &mcp.Implementation{Name: "test", Version: "v1.0.0"}

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

func newTestProvider(t *testing.T) (*credentialsprovider.Provider, store.TokenStore) {
	t.Helper()
	credsStore := store.NewMemoryTokenStore()
	pendingStore := store.NewMemoryPendingStore()

	p, err := credentialsprovider.New(credentialsprovider.Options{
		Name: "test-service",
		Variables: map[string]credentialsprovider.Variable{
			"pat": credentialsprovider.NewVariable("Personal Access Token", credentialsprovider.FieldPassword),
		},
		ServerBaseURL: "https://mcp.example.com",
		CredsStore:    credsStore,
		PendingStore:  pendingStore,
		TokenTimeout:  2 * time.Second,
	})
	require.NoError(t, err)
	return p, credsStore
}

func contextWithUser(sub string) context.Context {
	return middleware.WithUser(context.Background(), middleware.User{Sub: sub})
}

func extractEntryToken(t *testing.T, elicitedURL string) string {
	t.Helper()
	parsed, err := url.Parse(elicitedURL)
	require.NoError(t, err)
	token := parsed.Query().Get("t")
	require.NotEmpty(t, token, "elicited URL must carry a 't' param: %s", elicitedURL)
	return token
}

func TestRequireCredentials_CachedCredentials_SkipsElicitation(t *testing.T) {
	ctx := context.Background()
	p, credsStore := newTestProvider(t)
	require.NoError(t, credsStore.Set(ctx, "user-1", map[string]any{"pat": "cached-pat"}))

	session := connectedSession(t, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		t.Fatal("elicitation should not be triggered when credentials already exist")
		return nil, nil
	})

	var gotCreds map[string]any
	handler := p.RequireCredentials(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		gotCreds, _ = credentialsprovider.CredentialsFromContext(ctx)
		return &mcp.CallToolResult{}, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.NoError(t, err)
	require.Equal(t, "cached-pat", gotCreds["pat"])
}

func TestRequireCredentials_FailFast_ReturnsURLElicitationRequiredError(t *testing.T) {
	p, _ := newTestProvider(t)

	handler := p.RequireCredentials(true)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called when no credentials exist and failFast is true")
		return nil, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: nil})
	require.Error(t, err)

	var rpcErr *jsonrpc.Error
	require.True(t, errors.As(err, &rpcErr))
	require.EqualValues(t, mcp.CodeURLElicitationRequired, rpcErr.Code)
}

func TestRequireCredentials_BlockingFlow_CompletesViaSubmit(t *testing.T) {
	p, _ := newTestProvider(t)

	elicitedURLCh := make(chan string, 1)
	session := connectedSession(t, func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		elicitedURLCh <- req.Params.URL
		return &mcp.ElicitResult{Action: "accept"}, nil
	})

	go func() {
		elicitedURL := <-elicitedURLCh
		entryToken := extractEntryToken(t, elicitedURL)

		// GET the entry form first, mirroring the real browser flow.
		entryRec := httptest.NewRecorder()
		entryReq := httptest.NewRequest(http.MethodGet, "/credentials/test-service/entry?t="+entryToken, nil)
		p.HandleEntry(entryRec, entryReq)
		require.Equal(t, http.StatusOK, entryRec.Code)

		submitRec := httptest.NewRecorder()
		body := url.Values{"pat": {"submitted-pat"}}.Encode()
		submitReq := httptest.NewRequest(http.MethodPost, "/credentials/test-service/submit?t="+entryToken, strings.NewReader(body))
		submitReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		p.HandleSubmit(submitRec, submitReq)
		require.Equal(t, http.StatusOK, submitRec.Code)
	}()

	var gotCreds map[string]any
	handler := p.RequireCredentials(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		gotCreds, _ = credentialsprovider.CredentialsFromContext(ctx)
		return &mcp.CallToolResult{}, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.NoError(t, err)
	require.Equal(t, "submitted-pat", gotCreds["pat"])
}

func TestRequireCredentials_MissingRequiredField_RejectedAtSubmit(t *testing.T) {
	p, _ := newTestProvider(t)

	elicitedURLCh := make(chan string, 1)
	session := connectedSession(t, func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		elicitedURLCh <- req.Params.URL
		return &mcp.ElicitResult{Action: "accept"}, nil
	})

	go func() {
		elicitedURL := <-elicitedURLCh
		entryToken := extractEntryToken(t, elicitedURL)

		submitRec := httptest.NewRecorder()
		body := url.Values{"pat": {""}}.Encode() // empty required field
		submitReq := httptest.NewRequest(http.MethodPost, "/credentials/test-service/submit?t="+entryToken, strings.NewReader(body))
		submitReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		p.HandleSubmit(submitRec, submitReq)
		require.Equal(t, http.StatusBadRequest, submitRec.Code)
	}()

	handler := p.RequireCredentials(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called — submission was rejected for a missing required field")
		return nil, nil
	})

	result, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.NoError(t, err)
	require.True(t, result.IsError) // times out since the rejected submit never signaled success
}

func TestRequireCredentials_DuplicateSubmit_SecondIsRejected(t *testing.T) {
	// Drive the flow through Create directly (bypassing elicitation) to
	// isolate the double-submit behavior.
	ctx := context.Background()
	entryToken := "fixed-token-for-test"
	pendingStore := store.NewMemoryPendingStore()
	p, err := credentialsprovider.New(credentialsprovider.Options{
		Name:          "test-service-2",
		Variables:     map[string]credentialsprovider.Variable{"pat": credentialsprovider.NewVariable("PAT", credentialsprovider.FieldPassword)},
		ServerBaseURL: "https://mcp.example.com",
		CredsStore:    store.NewMemoryTokenStore(),
		PendingStore:  pendingStore,
	})
	require.NoError(t, err)
	require.NoError(t, pendingStore.Create(ctx, entryToken, map[string]any{"sub": "user-1"}, 60))

	body := url.Values{"pat": {"first-value"}}.Encode()
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/credentials/test-service-2/submit?t="+entryToken, strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.HandleSubmit(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/credentials/test-service-2/submit?t="+entryToken, strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.HandleSubmit(rec2, req2)
	require.Equal(t, http.StatusBadRequest, rec2.Code, "a second submit with the same (already-popped) entry token must be rejected")
}

func TestRequireCredentials_UserDeclines_ReturnsError(t *testing.T) {
	p, _ := newTestProvider(t)

	session := connectedSession(t, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	handler := p.RequireCredentials(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called when the user declines")
		return nil, nil
	})

	_, err := handler(contextWithUser("user-1"), &mcp.CallToolRequest{Session: session})
	require.Error(t, err)
}

func TestRequireCredentials_NoUserInContext_ReturnsErrorResult(t *testing.T) {
	p, _ := newTestProvider(t)

	handler := p.RequireCredentials(false)(func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("next should not be called without an authenticated user")
		return nil, nil
	})

	result, err := handler(context.Background(), &mcp.CallToolRequest{})
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestOpenPaths_ReturnsEntryAndSubmitPaths(t *testing.T) {
	p, _ := newTestProvider(t)
	require.ElementsMatch(t, []string{"/credentials/test-service/entry", "/credentials/test-service/submit"}, p.OpenPaths())
}
