package service

import (
	"context"
	"net/http"
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service/openaiagent"
)

type OpenAIAgentIdentityRegistrationInput struct {
	AccessToken string
	ProxyID     *int64
}

type OpenAIAgentIdentityRegistrationResult = openaiagent.Result

func (s *OpenAIOAuthService) RegisterAgentIdentity(
	ctx context.Context,
	input OpenAIAgentIdentityRegistrationInput,
) (*OpenAIAgentIdentityRegistrationResult, error) {
	proxyURL, err := s.agentIdentityRegistrationProxyURL(ctx, input.ProxyID)
	if err != nil {
		return nil, err
	}
	if s == nil || s.privacyClientFactory == nil {
		return nil, infraerrors.New(http.StatusInternalServerError, "OPENAI_AGENT_IDENTITY_CLIENT_UNAVAILABLE", "agent registration client is unavailable")
	}
	return openaiagent.Register(ctx, openaiagent.Input{
		AccessToken: strings.TrimSpace(input.AccessToken),
		ProxyURL:    proxyURL,
		BaseURL:     openAIAgentIdentityAuthAPIBaseURL,
	}, openaiagent.ClientFactory(s.privacyClientFactory))
}

func (s *OpenAIOAuthService) agentIdentityRegistrationProxyURL(ctx context.Context, proxyID *int64) (string, error) {
	if proxyID == nil {
		return "", nil
	}
	if s == nil || s.proxyRepo == nil {
		return "", infraerrors.New(http.StatusInternalServerError, "OPENAI_AGENT_IDENTITY_PROXY_UNAVAILABLE", "proxy repository is unavailable")
	}
	proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
	if err != nil || proxy == nil {
		return "", infraerrors.New(http.StatusBadRequest, "OPENAI_AGENT_IDENTITY_PROXY_NOT_FOUND", "proxy not found")
	}
	return proxy.URL(), nil
}
