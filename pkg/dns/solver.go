package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const defaultTXTTTL = 300

type wixSolver struct {
	name   string
	client kubernetes.Interface
}

type secretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type wixDNSProviderConfig struct {
	AccountIDSecretRef     secretKeyRef `json:"accountIdSecretRef"`
	AuthorizationSecretRef secretKeyRef `json:"authorizationSecretRef"`
	TTL                    int          `json:"ttl,omitempty"`
	BaseURL                string       `json:"baseURL,omitempty"`
}

func (e *wixSolver) Name() string {
	return e.name
}

func (e *wixSolver) Present(ch *acme.ChallengeRequest) error {
	zone, hostName, err := e.challengeTXTTarget(ch)
	if err != nil {
		klog.ErrorS(err, "Failed to determine TXT target for present", "namespace", ch.ResourceNamespace)
		return err
	}
	klog.InfoS("Presenting ACME TXT record", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName)

	client, ttl, err := e.clientFromChallengeConfig(ch)
	if err != nil {
		klog.ErrorS(err, "Failed to build Wix client for present", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName)
		return err
	}

	if err := client.AddTXTRecord(context.Background(), zone, hostName, ch.Key, ttl); err != nil {
		klog.ErrorS(err, "Failed to present ACME TXT record", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName, "ttl", ttl)
		return fmt.Errorf("present TXT record for %q in zone %q: %w", hostName, zone, err)
	}
	klog.InfoS("Presented ACME TXT record", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName, "ttl", ttl)

	return nil
}

func (e *wixSolver) CleanUp(ch *acme.ChallengeRequest) error {
	zone, hostName, err := e.challengeTXTTarget(ch)
	if err != nil {
		klog.ErrorS(err, "Failed to determine TXT target for cleanup", "namespace", ch.ResourceNamespace)
		return err
	}
	klog.InfoS("Cleaning up ACME TXT record", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName)

	client, ttl, err := e.clientFromChallengeConfig(ch)
	if err != nil {
		klog.ErrorS(err, "Failed to build Wix client for cleanup", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName)
		return err
	}

	if err := client.DeleteTXTRecord(context.Background(), zone, hostName, ch.Key, ttl); err != nil {
		klog.ErrorS(err, "Failed to clean up ACME TXT record", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName, "ttl", ttl)
		return fmt.Errorf("cleanup TXT record for %q in zone %q: %w", hostName, zone, err)
	}
	klog.InfoS("Cleaned up ACME TXT record", "namespace", ch.ResourceNamespace, "zone", zone, "hostName", hostName, "ttl", ttl)

	return nil
}

func (e *wixSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	if kubeClientConfig == nil {
		klog.Warningf("Initialize called with nil Kubernetes config; solver will fail until initialized with a valid config")
		return nil
	}

	k8sClient, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		klog.ErrorS(err, "Failed to initialize Kubernetes client")
		return err
	}
	e.client = k8sClient
	klog.InfoS("Initialized Kubernetes client for Wix solver")

	return nil
}

func (e *wixSolver) clientFromChallengeConfig(ch *acme.ChallengeRequest) (*Client, int, error) {
	if e.client == nil {
		return nil, 0, fmt.Errorf("kubernetes client is not initialized")
	}

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.ErrorS(err, "Failed to decode solver config", "namespace", ch.ResourceNamespace)
		return nil, 0, err
	}

	accountID, err := e.secretValue(ch.ResourceNamespace, cfg.AccountIDSecretRef)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve accountId from secret: %w", err)
	}

	authRaw, err := e.secretValue(ch.ResourceNamespace, cfg.AuthorizationSecretRef)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve authorization from secret: %w", err)
	}
	authHeader := normalizeAuthHeader(authRaw)

	opts := make([]ClientOption, 0, 1)
	if strings.TrimSpace(cfg.BaseURL) != "" {
		opts = append(opts, WithBaseURL(cfg.BaseURL))
	}

	client, err := NewClient(accountID, authHeader, opts...)
	if err != nil {
		klog.ErrorS(err, "Failed to construct Wix API client", "namespace", ch.ResourceNamespace)
		return nil, 0, err
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		klog.Warningf("Solver TTL is not set or invalid (%d); using default TTL %d", cfg.TTL, defaultTXTTTL)
		ttl = defaultTXTTTL
	}

	return client, ttl, nil
}

func (e *wixSolver) secretValue(namespace string, ref secretKeyRef) (string, error) {
	if strings.TrimSpace(namespace) == "" {
		return "", fmt.Errorf("resource namespace is required")
	}
	if strings.TrimSpace(ref.Name) == "" || strings.TrimSpace(ref.Key) == "" {
		return "", fmt.Errorf("secret ref must include name and key")
	}

	sec, err := e.client.CoreV1().Secrets(namespace).Get(context.Background(), ref.Name, metav1.GetOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to read secret", "namespace", namespace, "secretName", ref.Name)
		return "", err
	}

	val, ok := sec.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %q", ref.Key, ref.Name)
	}

	out := strings.TrimSpace(string(val))
	if out == "" {
		return "", fmt.Errorf("key %q in secret %q is empty", ref.Key, ref.Name)
	}
	return out, nil
}

func loadConfig(cfgJSON *extapi.JSON) (wixDNSProviderConfig, error) {
	cfg := wixDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decode solver config: %w", err)
	}
	return cfg, nil
}

func normalizeAuthHeader(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.ContainsRune(s, ' ') {
		return s
	}
	return "Bearer " + s
}

func (e *wixSolver) challengeTXTTarget(ch *acme.ChallengeRequest) (zone string, hostName string, err error) {
	zone = normalizeDNSName(ch.ResolvedZone)
	hostName = normalizeDNSName(ch.ResolvedFQDN)

	if zone == "" {
		return "", "", fmt.Errorf("challenge resolved zone is empty")
	}
	if hostName == "" {
		return "", "", fmt.Errorf("challenge resolved fqdn is empty")
	}
	if hostName != zone && !strings.HasSuffix(hostName, "."+zone) {
		return "", "", fmt.Errorf("resolved fqdn %q is not within resolved zone %q", hostName, zone)
	}

	return zone, hostName, nil
}

func New(name string) webhook.Solver {
	if name == "" {
		// by default
		name = "wix"
	}
	return &wixSolver{name: name}
}
