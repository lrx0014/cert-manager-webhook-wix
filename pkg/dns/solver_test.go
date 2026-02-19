package dns

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWixSolver_Name(t *testing.T) {
	solver := New("")
	assert.Equal(t, "wix", solver.Name())
}

func TestWixSolver_Initialize(t *testing.T) {
	solver := New("")
	done := make(chan struct{})
	err := solver.Initialize(nil, done)
	assert.NoError(t, err, "Expected Initialize not to error")
	close(done)
}

func TestWixSolver_Present_Cleanup(t *testing.T) {
	type capturedRequest struct {
		method  string
		path    string
		account string
		auth    string
		body    patchDNSZoneRequest
	}

	requests := make(chan capturedRequest, 2)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var body patchDNSZoneRequest
		err = json.Unmarshal(data, &body)
		require.NoError(t, err)

		requests <- capturedRequest{
			method:  r.Method,
			path:    r.URL.Path,
			account: r.Header.Get("wix-account-id"),
			auth:    r.Header.Get("Authorization"),
			body:    body,
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rawCfg := []byte(`{
		"accountIdSecretRef":{"name":"wix-api","key":"account-id"},
		"authorizationSecretRef":{"name":"wix-api","key":"authorization"},
		"ttl":120,
		"baseURL":"` + ts.URL + `"
	}`)
	cfg := &extapi.JSON{Raw: rawCfg}

	solver := New("").(*wixSolver)
	solver.client = fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wix-api",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"account-id":    []byte("acct-1"),
			"authorization": []byte("token-1"),
		},
	})

	challenge := &acme.ChallengeRequest{
		Action:            acme.ChallengeActionPresent,
		Type:              "dns-01",
		ResolvedZone:      "example.com.",
		ResolvedFQDN:      "_acme-challenge.example.com.",
		Key:               "txt-token",
		ResourceNamespace: "test-ns",
		Config:            cfg,
	}

	err := solver.Present(challenge)
	require.NoError(t, err)

	challenge.Action = acme.ChallengeActionCleanUp
	err = solver.CleanUp(challenge)
	require.NoError(t, err)

	presentReq := <-requests
	cleanupReq := <-requests

	assert.Equal(t, http.MethodPatch, presentReq.method)
	assert.Equal(t, "/domains/v1/dns-zones/example.com", presentReq.path)
	assert.Equal(t, "acct-1", presentReq.account)
	assert.Equal(t, "Bearer token-1", presentReq.auth)
	require.Len(t, presentReq.body.Additions, 1)
	assert.Empty(t, presentReq.body.Deletions)
	assert.Equal(t, "example.com", presentReq.body.DomainName)
	assert.Equal(t, DNSRecordChange{
		Values:   []string{"txt-token"},
		Type:     "TXT",
		HostName: "_acme-challenge.example.com",
		TTL:      120,
	}, presentReq.body.Additions[0])

	assert.Equal(t, http.MethodPatch, cleanupReq.method)
	assert.Equal(t, "/domains/v1/dns-zones/example.com", cleanupReq.path)
	assert.Equal(t, "acct-1", cleanupReq.account)
	assert.Equal(t, "Bearer token-1", cleanupReq.auth)
	require.Len(t, cleanupReq.body.Deletions, 1)
	assert.Empty(t, cleanupReq.body.Additions)
	assert.Equal(t, "example.com", cleanupReq.body.DomainName)
	assert.Equal(t, DNSRecordChange{
		Values:   []string{"txt-token"},
		Type:     "TXT",
		HostName: "_acme-challenge.example.com",
		TTL:      120,
	}, cleanupReq.body.Deletions[0])
}
