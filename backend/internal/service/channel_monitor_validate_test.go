package service

import "testing"

func TestValidateEndpointAllowsHTTPWhenConfigured(t *testing.T) {
	t.Parallel()
	opts := endpointValidationOptions{AllowInsecureHTTP: true}
	if err := validateEndpoint("http://example.com", opts); err != nil {
		t.Fatalf("validateEndpoint returned error: %v", err)
	}
}

func TestValidateEndpointRejectsHTTPByDefault(t *testing.T) {
	t.Parallel()
	err := validateEndpoint("http://example.com", endpointValidationOptions{})
	if err == nil {
		t.Fatal("validateEndpoint expected scheme error")
	}
	if err != ErrChannelMonitorEndpointScheme {
		t.Fatalf("validateEndpoint error = %v, want %v", err, ErrChannelMonitorEndpointScheme)
	}
}

func TestValidateEndpointAllowsPrivateHostWhenConfigured(t *testing.T) {
	t.Parallel()
	opts := endpointValidationOptions{
		AllowInsecureHTTP: true,
		AllowPrivateHosts: true,
	}
	if err := validateEndpoint("http://192.168.2.6:8083", opts); err != nil {
		t.Fatalf("validateEndpoint returned error: %v", err)
	}
}

func TestValidateEndpointRejectsPrivateHostByDefault(t *testing.T) {
	t.Parallel()
	opts := endpointValidationOptions{AllowInsecureHTTP: true}
	err := validateEndpoint("http://192.168.2.6:8083", opts)
	if err == nil {
		t.Fatal("validateEndpoint expected private host error")
	}
	if err != ErrChannelMonitorEndpointPrivate {
		t.Fatalf("validateEndpoint error = %v, want %v", err, ErrChannelMonitorEndpointPrivate)
	}
}
