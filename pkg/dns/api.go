package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

const defaultWixAPIBaseURL = "https://www.wixapis.com"

// DNSRecordChange represents one record mutation in Wix DNS PATCH requests.
type DNSRecordChange struct {
	Values   []string `json:"values"`
	Type     string   `json:"type"`
	HostName string   `json:"hostName"`
	TTL      int      `json:"ttl,omitempty"`
}

type patchDNSZoneRequest struct {
	Deletions  []DNSRecordChange `json:"deletions,omitempty"`
	Additions  []DNSRecordChange `json:"additions,omitempty"`
	DomainName string            `json:"domainName"`
}

// Client wraps Wix DNS zone mutation APIs.
type Client struct {
	baseURL    string
	accountID  string
	authHeader string
	httpClient *http.Client
}

// ClientOption configures the Wix API client.
type ClientOption func(*Client)

// WithHTTPClient injects a custom http.Client (useful for tests and retries).
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithBaseURL overrides the Wix API base URL (useful for tests).
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

// NewClient creates a Wix DNS API client.
// authHeader should be the full Authorization header value (for example: "Bearer <token>").
func NewClient(accountID, authHeader string, opts ...ClientOption) (*Client, error) {
	if strings.TrimSpace(accountID) == "" {
		return nil, fmt.Errorf("accountID is required")
	}
	if strings.TrimSpace(authHeader) == "" {
		return nil, fmt.Errorf("authHeader is required")
	}

	c := &Client{
		baseURL:    defaultWixAPIBaseURL,
		accountID:  accountID,
		authHeader: authHeader,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// PatchDNSZone applies additions/deletions to a Wix DNS zone.
func (c *Client) PatchDNSZone(ctx context.Context, domainName string, additions, deletions []DNSRecordChange) error {
	domainName = normalizeDNSName(domainName)
	if domainName == "" {
		return fmt.Errorf("domainName is required")
	}

	reqBody := patchDNSZoneRequest{
		DomainName: domainName,
		Additions:  additions,
		Deletions:  deletions,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal wix patch request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/domains/v1/dns-zones/%s", c.baseURL, url.PathEscape(domainName))
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create wix request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("wix-account-id", c.accountID)
	req.Header.Set("Authorization", c.authHeader)

	klog.V(4).InfoS(
		"Wix API request",
		"method", req.Method,
		"url", req.URL.String(),
		"params", req.URL.RawQuery,
		"body", string(body),
	)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("wix patch dns zone request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("read wix patch dns zone response: %w", err)
	}
	respBodyText := strings.TrimSpace(string(respBody))

	klog.V(4).InfoS(
		"Wix API response",
		"method", req.Method,
		"url", req.URL.String(),
		"statusCode", resp.StatusCode,
		"body", respBodyText,
	)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msgText := respBodyText
		if msgText == "" {
			msgText = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("wix patch dns zone failed: status=%d body=%q", resp.StatusCode, msgText)
	}

	return nil
}

// AddTXTRecord adds a TXT record in the given zone.
func (c *Client) AddTXTRecord(ctx context.Context, zone, hostName, value string, ttl int) error {
	change := DNSRecordChange{
		Values:   []string{value},
		Type:     "TXT",
		HostName: normalizeDNSName(hostName),
		TTL:      ttl,
	}
	return c.PatchDNSZone(ctx, zone, []DNSRecordChange{change}, nil)
}

// DeleteTXTRecord removes one TXT record value in the given zone.
func (c *Client) DeleteTXTRecord(ctx context.Context, zone, hostName, value string, ttl int) error {
	change := DNSRecordChange{
		Values:   []string{value},
		Type:     "TXT",
		HostName: normalizeDNSName(hostName),
		TTL:      ttl,
	}
	return c.PatchDNSZone(ctx, zone, nil, []DNSRecordChange{change})
}

func normalizeDNSName(s string) string {
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}
