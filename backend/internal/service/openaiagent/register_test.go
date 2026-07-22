package openaiagent

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
)

func TestRegisterFromSession(t *testing.T) {
	accessToken := testToken(t, time.Now().Add(time.Hour), "account-1", "user-1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+accessToken, r.Header.Get("Authorization"))
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Contains(t, body["agent_public_key"], "ssh-ed25519 ")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"agent_runtime_id":"runtime-1"}`))
	}))
	defer server.Close()

	result, err := Register(context.Background(), Input{
		AccessToken: accessToken,
		BaseURL:     server.URL,
	}, func(string) (*req.Client, error) { return req.C(), nil })

	require.NoError(t, err)
	require.Equal(t, "runtime-1", result.AgentRuntimeID)
	require.Equal(t, "account-1", result.AccountID)
	require.Equal(t, "user-1", result.UserID)
	require.Equal(t, "user@example.com", result.Email)
	require.Equal(t, "plus", result.PlanType)
	assertPrivateKey(t, result.PrivateKey)
}

func TestRegisterRejectsExpiredSession(t *testing.T) {
	token := testToken(t, time.Now().Add(-time.Hour), "account-1", "user-1")
	_, err := Register(context.Background(), Input{AccessToken: token}, nil)
	require.ErrorContains(t, err, "expired")
}

func TestRegisterRequiresAccountClaims(t *testing.T) {
	token := testToken(t, time.Now().Add(time.Hour), "", "")
	_, err := Register(context.Background(), Input{AccessToken: token}, nil)
	require.ErrorContains(t, err, "chatgpt_account_id")
}

func testToken(t *testing.T, expiresAt time.Time, accountID, userID string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"exp": expiresAt.Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID, "chatgpt_user_id": userID, "chatgpt_plan_type": "plus",
		},
		"https://api.openai.com/profile": map[string]any{"email": "user@example.com"},
	})
	require.NoError(t, err)
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func assertPrivateKey(t *testing.T, encoded string) {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	key, err := x509.ParsePKCS8PrivateKey(der)
	require.NoError(t, err)
	require.IsType(t, ed25519.PrivateKey{}, key)
}
