package admin

import (
	"context"
	"errors"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type agentIdentityRegistrationService interface {
	RegisterAgentIdentity(
		ctx context.Context,
		input service.OpenAIAgentIdentityRegistrationInput,
	) (*service.OpenAIAgentIdentityRegistrationResult, error)
}

func (h *AccountHandler) SetAgentIdentityRegistrationService(registrar agentIdentityRegistrationService) {
	h.agentIdentityRegistration = registrar
}

func (h *AccountHandler) registerCodexAgentIdentityEntries(
	ctx context.Context,
	req CodexSessionImportRequest,
	entries []codexImportEntry,
) []codexImportEntry {
	registered := make([]codexImportEntry, 0, len(entries))
	for _, entry := range entries {
		registered = append(registered, h.registerCodexAgentIdentityEntry(ctx, req, entry))
	}
	return registered
}

func (h *AccountHandler) registerCodexAgentIdentityEntry(
	ctx context.Context,
	req CodexSessionImportRequest,
	entry codexImportEntry,
) codexImportEntry {
	if h == nil || h.agentIdentityRegistration == nil {
		entry.Err = errors.New("agent identity 注册服务不可用")
		return entry
	}
	accessToken, err := agentIdentitySessionAccessToken(entry.Value)
	if err != nil {
		entry.Err = err
		return entry
	}
	result, err := h.agentIdentityRegistration.RegisterAgentIdentity(ctx, service.OpenAIAgentIdentityRegistrationInput{
		AccessToken: accessToken,
		ProxyID:     req.ProxyID,
	})
	if err != nil {
		entry.Err = err
		return entry
	}
	entry.Value = agentIdentityImportValue(result)
	return entry
}

func agentIdentitySessionAccessToken(value any) (string, error) {
	record, ok := value.(map[string]any)
	if !ok {
		return "", errors.New("请输入包含 accessToken 的 Session JSON 对象")
	}
	accessToken := firstCodexString(record,
		[]string{"accessToken"},
		[]string{"access_token"},
		[]string{"tokens", "accessToken"},
		[]string{"tokens", "access_token"},
	)
	if strings.TrimSpace(accessToken) == "" {
		return "", errors.New("session JSON 缺少 accessToken")
	}
	return strings.TrimSpace(accessToken), nil
}

func agentIdentityImportValue(result *service.OpenAIAgentIdentityRegistrationResult) map[string]any {
	return map[string]any{
		"auth_mode": service.OpenAIAuthModeAgentIdentity,
		"agent_identity": map[string]any{
			"agent_runtime_id":           result.AgentRuntimeID,
			"agent_private_key":          result.PrivateKey,
			"account_id":                 result.AccountID,
			"chatgpt_user_id":            result.UserID,
			"email":                      result.Email,
			"plan_type":                  result.PlanType,
			"chatgpt_account_is_fedramp": result.FedRAMP,
		},
	}
}
