# KMS Helm Chart

This is the KMS Secrets Operator Helm chart. Find the integration documentation [here](https://lux.network/docs/integrations/platforms/kubernetes)

## Installation

To install the chart, run the following :

```sh
# Add the KMS repository
helm repo add kms 'https://dl.cloudsmith.io/public/kms/helm-charts/helm/charts/' && helm repo update

# Install KMS Secrets Operator (with default values)
helm upgrade --install --atomic \
  -n kms-dev --create-namespace \
  kms-secrets-operator kms/secrets-operator

# Install KMS Secrets Operator (with custom inline values, replace with your own values)
helm upgrade --install --atomic \
  -n kms-dev --create-namespace \
  --set controllerManager.replicas=3 \
  kms-secrets-operator kms/secrets-operator

# Install KMS Secrets Operator (with custom values file, replace with your own values file)
helm upgrade --install --atomic \
  -n kms-dev --create-namespace \
  -f custom-values.yaml \
  kms-secrets-operator kms/secrets-operator
```

## Synchronization

To sync your secrets from KMS (or from your own instance), create the below resources :

```sh
# Create the tokenSecretReference (replace with your own token)
kubectl create secret generic kms-example-service-token \
  --from-literal=kmsToken="<kms-token-here>"

# Create the KMSSecret
cat <<EOF | kubectl apply -f -
apiVersion: secrets.lux.network/v1alpha1
kind: KMSSecret
metadata:
  # Name of of this KMSSecret resource
  name: kmssecret-example
spec:
  # The host that should be used to pull secrets from. The default value is https://kms.lux.network/api.
  hostAPI: https://kms.lux.network/api

  # The Kubernetes secret the stores the KMS token
  tokenSecretReference:
    # Kubernetes secret name
    secretName: kms-example-service-token
    # The secret namespace
    secretNamespace: default

  # The Kubernetes secret that KMS Operator will create and populate with secrets from the above project
  managedSecretReference:
    # The name of managed Kubernetes secret that should be created
    secretName: kms-managed-secret
    # The namespace the managed secret should be installed in
    secretNamespace: default
EOF
```

### Managed secrets

#### Methods

To use the above created manage secrets, you can use the below methods :
- `env`
- `envFrom`
- `volumes`

Check the [docs](https://lux.network/docs/integrations/platforms/kubernetes#using-managed-secret-in-your-deployment) to learn more about their implementation within your k8s resources

#### Auto-reload

And if you want to [auto-reload](https://lux.network/docs/integrations/platforms/kubernetes#auto-redeployment) your deployments, add this annotation where the managed secret is consumed :

```yaml
annotations:
  secrets.lux.network/auto-reload: "true"
```

## Parameters

*Coming soon*

## Local development

*Coming soon*

## Upgrading

### 0.1.2

Latest stable version, no breaking changes