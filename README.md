# ACME webhook for Wix DNS API

This kubernetes webhook can be used when you want to use cert-manager with Wix DNS API. 

- [Wix DNS API docs](https://dev.wix.com/docs/api-reference/account-level/domains/domain-dns/update-dns-zone)

## Requirements

- [go](https://golang.org/) >= 1.25.0
- [helm](https://helm.sh/) >= v3.0.0
- [kubernetes](https://kubernetes.io/) >= v1.14.0
- [cert-manager](https://cert-manager.io/) >= 0.12.0

## Installation

### cert-manager

Follow the [instructions](https://cert-manager.io/docs/installation/) using the cert-manager documentation to install it within your cluster.

### Webhook

#### Using public helm chart

```bash
helm repo add cert-manager-webhook-wix https://lrx0014.github.io/cert-manager-webhook-wix
helm install --namespace cert-manager cert-manager-webhook-wix cert-manager-webhook-wix/cert-manager-webhook-wix
```

#### From local checkout

```bash
helm install --namespace cert-manager cert-manager-webhook-wix deploy/cert-manager-webhook-wix
```

**Note**: The kubernetes resources used to install the Webhook should be deployed within the same namespace as the cert-manager.

To uninstall the webhook:

```bash
helm uninstall --namespace cert-manager cert-manager-webhook-wix
```

## Issuer

Create a `ClusterIssuer` or `Issuer` resource as following:
(Keep in Mind that the Example uses the Staging URL from Let's Encrypt. Look at [Getting Start](https://letsencrypt.org/getting-started/) for using the normal Let's Encrypt URL.)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: wix-letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging-v02.api.letsencrypt.org/directory

    # Email address used for ACME registration
    email: mail@example.com

    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-staging

    solvers:
      - dns01:
          webhook:
            config:
              # specify your secret that stores your wix api token credentials
              # it's possible to store account-id and auth token in separate secrets if needed
              accountIdSecretRef:
                name: wix-api-token
                key: account-id
              authorizationSecretRef:
                name: wix-api-token
                key: authorization
            groupName: wix.cert-manager-webhook.lrx0014.github.com
            solverName: wix
```

### Credentials

In order to access the Wix API, the webhook needs an API token.

- https://manage.wix.com/account/api-keys

The secret for the example above will look like this:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: wix-api-token
  namespace: cert-manager
type: Opaque
data:
  account-id: <your-account-id>
  authorization: <your-auth-key>
```

### Create a certificate

Finally you can create certificates, for example:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-wix-cert
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - example.com
  privateKey:
    rotationPolicy: Never
  issuerRef:
    name: wix-letsencrypt-staging
    kind: ClusterIssuer
  secretName: wix-example-cert
```

## Development

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

First, you need to have Wix account with access to DNS management panel. You need to create API token and get your account-id and have a registered site and DNS zone there.

You can then run the test suite with:

- TODO

## Creating new package

To build new Docker image and push it to gfcr.io, here is a github action manifest:

- [.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml)

To compile and publish new Helm chart version:

```shell
helm package deploy/cert-manager-webhook-wix
git checkout gh-pages
helm repo index . --url https://lrx0014.github.io/cert-manager-webhook-wix/
```
