# Kubernetes / AKS Deployment

SentinelWeave ships a production-ready **Helm chart** for deployment to
Azure Kubernetes Service (AKS) or any other Kubernetes cluster.

---

## Prerequisites

| Tool | Minimum version | Install |
|---|---|---|
| `kubectl` | 1.28 | [docs](https://kubernetes.io/docs/tasks/tools/) |
| `helm` | 3.12 | [docs](https://helm.sh/docs/intro/install/) |
| Azure CLI (`az`) | 2.55 | [docs](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| Docker | 24 | [docs](https://docs.docker.com/get-docker/) |

---

## 1 — Build and push the container image

```bash
# Authenticate to Azure Container Registry
az acr login --name <your-acr-name>

# Build the image
docker build -t <your-acr-name>.azurecr.io/sentinel-weave:0.4.0 .

# Push
docker push <your-acr-name>.azurecr.io/sentinel-weave:0.4.0
```

---

## 2 — Create an AKS cluster (if you don't have one)

```bash
az group create --name sentinel-rg --location uksouth

az aks create \
  --resource-group sentinel-rg \
  --name sentinel-aks \
  --node-count 2 \
  --node-vm-size Standard_DS2_v2 \
  --generate-ssh-keys \
  --attach-acr <your-acr-name>

az aks get-credentials --resource-group sentinel-rg --name sentinel-aks
```

---

## 3 — Deploy with Helm

### Minimal deployment (demo mode, no Azure back-ends)

```bash
helm upgrade --install sentinel-weave ./helm/sentinel-weave \
  --set image.repository=<your-acr-name>.azurecr.io/sentinel-weave \
  --set image.tag=0.4.0
```

### Production deployment with Azure integration

```bash
helm upgrade --install sentinel-weave ./helm/sentinel-weave \
  --set image.repository=<your-acr-name>.azurecr.io/sentinel-weave \
  --set image.tag=0.4.0 \
  --set env.SENTINELWEAVE_DEMO_MODE=false \
  --set azure.storageConnectionString="DefaultEndpointsProtocol=https;AccountName=...;..." \
  --set azure.textAnalyticsEndpoint="https://<resource>.cognitiveservices.azure.com/" \
  --set azure.textAnalyticsKey="<key>" \
  --set azure.appInsightsConnectionString="InstrumentationKey=...;..."
```

### Using a pre-existing Kubernetes Secret (recommended for CI/CD)

```bash
# Create the secret once
kubectl create secret generic sentinel-weave-azure \
  --from-literal=AZURE_STORAGE_CONNECTION_STRING="..." \
  --from-literal=AZURE_TEXT_ANALYTICS_KEY="..."

# Deploy referencing the secret
helm upgrade --install sentinel-weave ./helm/sentinel-weave \
  --set image.repository=<your-acr-name>.azurecr.io/sentinel-weave \
  --set image.tag=0.4.0 \
  --set existingSecret=sentinel-weave-azure
```

---

## 4 — Enable Ingress (optional)

The chart supports any `nginx`-compatible Ingress controller.  On AKS,
install the managed NGINX add-on first:

```bash
az aks enable-addons \
  --resource-group sentinel-rg \
  --name sentinel-aks \
  --addons http_application_routing
```

Then deploy with Ingress enabled:

```bash
helm upgrade --install sentinel-weave ./helm/sentinel-weave \
  --set ingress.enabled=true \
  --set "ingress.hosts[0].host=sentinel.example.com" \
  --set "ingress.hosts[0].paths[0].path=/" \
  --set "ingress.hosts[0].paths[0].pathType=Prefix" \
  --set "ingress.annotations.kubernetes\\.io/ingress\\.class=nginx"
```

To add TLS with cert-manager:

```bash
  --set "ingress.tls[0].secretName=sentinel-weave-tls" \
  --set "ingress.tls[0].hosts[0]=sentinel.example.com" \
  --set "ingress.annotations.cert-manager\\.io/cluster-issuer=letsencrypt-prod"
```

---

## 5 — Horizontal Pod Autoscaler

```bash
helm upgrade sentinel-weave ./helm/sentinel-weave \
  --reuse-values \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=10 \
  --set autoscaling.targetCPUUtilizationPercentage=60
```

---

## 6 — Persistent storage for reports

Enable a `PersistentVolumeClaim` so encrypted threat reports survive pod
restarts (backed by Azure Disk on AKS):

```bash
helm upgrade sentinel-weave ./helm/sentinel-weave \
  --reuse-values \
  --set persistence.enabled=true \
  --set persistence.size=10Gi \
  --set persistence.storageClass=managed-premium
```

---

## 7 — Verify the deployment

```bash
# Watch pods come up
kubectl get pods -l app.kubernetes.io/name=sentinel-weave -w

# Check the service
kubectl get svc sentinel-weave

# Port-forward if no Ingress
kubectl port-forward svc/sentinel-weave 8080:80

# Open the dashboard
open http://localhost:8080
```

---

## Available Helm values

| Value | Default | Description |
|---|---|---|
| `image.repository` | `sentinelweave` | Container image repository |
| `image.tag` | `0.4.0` | Container image tag |
| `replicaCount` | `1` | Number of pod replicas |
| `autoscaling.enabled` | `false` | Enable HPA |
| `autoscaling.minReplicas` | `1` | HPA minimum |
| `autoscaling.maxReplicas` | `5` | HPA maximum |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `ingress.enabled` | `false` | Enable Ingress resource |
| `ingress.className` | `""` | Ingress class name |
| `persistence.enabled` | `false` | Enable PVC |
| `persistence.size` | `1Gi` | PVC storage size |
| `persistence.storageClass` | `""` | Storage class (cluster default) |
| `existingSecret` | `""` | Name of existing secret for Azure creds |
| `azure.*` | `""` | Azure service credentials |
| `resources.requests.cpu` | `250m` | CPU request |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.limits.cpu` | `1` | CPU limit |
| `resources.limits.memory` | `1Gi` | Memory limit |

See `helm/sentinel-weave/values.yaml` for the full list with comments.

---

## Uninstall

```bash
helm uninstall sentinel-weave
```
