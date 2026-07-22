package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type agentIdentityRegistrationStub struct {
	result *service.OpenAIAgentIdentityRegistrationResult
	input  service.OpenAIAgentIdentityRegistrationInput
}

func (s *agentIdentityRegistrationStub) RegisterAgentIdentity(
	_ context.Context,
	input service.OpenAIAgentIdentityRegistrationInput,
) (*service.OpenAIAgentIdentityRegistrationResult, error) {
	s.input = input
	return s.result, nil
}

func TestRegisterCodexAgentIdentityEntriesCreatesAccountWithoutSessionToken(t *testing.T) {
	adminService := newCodexImportMemoryAdminService(nil)
	handler := NewAccountHandler(adminService, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	registrar := &agentIdentityRegistrationStub{result: agentIdentityRegistrationTestResult(t)}
	handler.SetAgentIdentityRegistrationService(registrar)
	req := CodexSessionImportRequest{SkipDefaultGroupBind: boolPtr(true)}
	entries := []codexImportEntry{{Index: 1, Value: map[string]any{"accessToken": "header.payload.signature"}}}

	registered := handler.registerCodexAgentIdentityEntries(context.Background(), req, entries)
	result, err := handler.importCodexSessions(context.Background(), req, registered)

	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
	require.Equal(t, "header.payload.signature", registrar.input.AccessToken)
	require.Len(t, adminService.createdAccounts, 1)
	credentials := adminService.createdAccounts[0].Credentials
	require.Equal(t, service.OpenAIAuthModeAgentIdentity, credentials["auth_mode"])
	require.NotContains(t, credentials, "access_token")
}

func TestRegisterCodexAgentIdentityEntriesReportsMissingToken(t *testing.T) {
	handler := NewAccountHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	handler.SetAgentIdentityRegistrationService(&agentIdentityRegistrationStub{})
	entries := []codexImportEntry{{Index: 1, Value: map[string]any{"user": map[string]any{}}}}

	registered := handler.registerCodexAgentIdentityEntries(context.Background(), CodexSessionImportRequest{}, entries)

	require.ErrorContains(t, registered[0].Err, "accessToken")
}

func agentIdentityRegistrationTestResult(t *testing.T) *service.OpenAIAgentIdentityRegistrationResult {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return &service.OpenAIAgentIdentityRegistrationResult{
		AgentRuntimeID: "runtime-1",
		PrivateKey:     base64.StdEncoding.EncodeToString(der),
		AccountID:      "account-1",
		UserID:         "user-1",
		Email:          "user@example.com",
		PlanType:       "plus",
	}
}
