package openaiagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/imroc/req/v3"
	"golang.org/x/crypto/ssh"
)

const (
	registrationTimeout = 30 * time.Second
	clockSkew           = 120 * time.Second
	agentVersion        = "0.138.0-alpha.6"
	agentHarnessID      = "codex-cli"
	runningLocation     = "local"
)

type ClientFactory func(proxyURL string) (*req.Client, error)

type Input struct {
	AccessToken string
	ProxyURL    string
	BaseURL     string
}

type Result struct {
	AgentRuntimeID string
	PrivateKey     string
	AccountID      string
	UserID         string
	Email          string
	PlanType       string
	FedRAMP        bool
}

type claims struct {
	Exp     int64 `json:"exp"`
	Auth    authClaims
	Profile profileClaims
}

type authClaims struct {
	AccountID string `json:"chatgpt_account_id"`
	UserID    string `json:"chatgpt_user_id"`
	PlanType  string `json:"chatgpt_plan_type"`
	FedRAMP   bool   `json:"chatgpt_account_is_fedramp"`
}

type profileClaims struct {
	Email string `json:"email"`
}

type registrationResponse struct {
	AgentRuntimeID string `json:"agent_runtime_id"`
}

func Register(ctx context.Context, input Input, clientFactory ClientFactory) (*Result, error) {
	parsedClaims, err := parseClaims(input.AccessToken)
	if err != nil {
		return nil, err
	}
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		return nil, infraerrors.New(http.StatusInternalServerError, "OPENAI_AGENT_IDENTITY_KEY_FAILED", err.Error())
	}
	runtimeID, err := registerRuntime(ctx, input, publicKey, clientFactory)
	if err != nil {
		return nil, err
	}
	return buildResult(parsedClaims, privateKey, runtimeID), nil
}

func parseClaims(token string) (*claims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, badToken("accessToken is not a valid JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, badToken("accessToken payload is not valid base64url")
	}
	var raw struct {
		Exp     int64         `json:"exp"`
		Auth    authClaims    `json:"https://api.openai.com/auth"`
		Profile profileClaims `json:"https://api.openai.com/profile"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, badToken("accessToken payload is not valid JSON")
	}
	parsed := &claims{Exp: raw.Exp, Auth: raw.Auth, Profile: raw.Profile}
	if err := validateClaims(parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func validateClaims(parsed *claims) error {
	if parsed.Exp > 0 && time.Now().After(time.Unix(parsed.Exp, 0).Add(clockSkew)) {
		return infraerrors.New(http.StatusBadRequest, "OPENAI_AGENT_IDENTITY_TOKEN_EXPIRED", "accessToken has expired")
	}
	if strings.TrimSpace(parsed.Auth.AccountID) == "" {
		return infraerrors.New(http.StatusBadRequest, "OPENAI_AGENT_IDENTITY_ACCOUNT_MISSING", "accessToken is missing chatgpt_account_id")
	}
	if strings.TrimSpace(parsed.Auth.UserID) == "" {
		return infraerrors.New(http.StatusBadRequest, "OPENAI_AGENT_IDENTITY_USER_MISSING", "accessToken is missing chatgpt_user_id")
	}
	return nil
}

func badToken(message string) error {
	return infraerrors.New(http.StatusBadRequest, "OPENAI_AGENT_IDENTITY_TOKEN_INVALID", message)
}

func generateKeyPair() (string, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", errors.New("failed to generate Ed25519 key")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", errors.New("failed to encode Ed25519 private key")
	}
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return "", "", errors.New("failed to encode Ed25519 public key")
	}
	encodedPrivate := base64.StdEncoding.EncodeToString(privateDER)
	encodedPublic := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))
	return encodedPrivate, encodedPublic, nil
}

func registerRuntime(ctx context.Context, input Input, publicKey string, clientFactory ClientFactory) (string, error) {
	if clientFactory == nil {
		return "", infraerrors.New(http.StatusInternalServerError, "OPENAI_AGENT_IDENTITY_CLIENT_UNAVAILABLE", "agent registration client is unavailable")
	}
	client, err := clientFactory(input.ProxyURL)
	if err != nil {
		return "", infraerrors.Newf(http.StatusBadGateway, "OPENAI_AGENT_IDENTITY_CLIENT_FAILED", "create registration client: %v", err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, registrationTimeout)
	defer cancel()
	var result registrationResponse
	resp, err := client.R().SetContext(requestCtx).
		SetHeader("Authorization", "Bearer "+strings.TrimSpace(input.AccessToken)).
		SetHeader("Content-Type", "application/json").
		SetBody(registrationBody(publicKey)).SetSuccessResult(&result).
		Post(strings.TrimRight(input.BaseURL, "/") + "/v1/agent/register")
	if err != nil {
		return "", infraerrors.Newf(http.StatusBadGateway, "OPENAI_AGENT_IDENTITY_REQUEST_FAILED", "agent registration request failed: %v", err)
	}
	if !resp.IsSuccessState() {
		return "", registrationStatusError(resp)
	}
	if strings.TrimSpace(result.AgentRuntimeID) == "" {
		return "", infraerrors.New(http.StatusBadGateway, "OPENAI_AGENT_IDENTITY_RESPONSE_INVALID", "agent registration response omitted agent_runtime_id")
	}
	return strings.TrimSpace(result.AgentRuntimeID), nil
}

func registrationStatusError(resp *req.Response) error {
	detail := strings.TrimSpace(resp.String())
	if len(detail) > 512 {
		detail = detail[:512]
	}
	return infraerrors.Newf(http.StatusBadGateway, "OPENAI_AGENT_IDENTITY_REGISTRATION_FAILED", "agent registration returned status %d: %s", resp.StatusCode, detail)
}

func registrationBody(publicKey string) map[string]any {
	return map[string]any{
		"abom": map[string]string{
			"agent_version": agentVersion, "agent_harness_id": agentHarnessID, "running_location": runningLocation,
		},
		"agent_public_key": publicKey,
	}
}

func buildResult(parsed *claims, privateKey, runtimeID string) *Result {
	planType := strings.TrimSpace(parsed.Auth.PlanType)
	if planType == "" {
		planType = "free"
	}
	return &Result{
		AgentRuntimeID: runtimeID,
		PrivateKey:     privateKey,
		AccountID:      strings.TrimSpace(parsed.Auth.AccountID),
		UserID:         strings.TrimSpace(parsed.Auth.UserID),
		Email:          strings.TrimSpace(parsed.Profile.Email),
		PlanType:       planType,
		FedRAMP:        parsed.Auth.FedRAMP,
	}
}
