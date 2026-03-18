#!/usr/bin/env bash
set -euo pipefail

python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

if ! command -v kind >/dev/null 2>&1; then
  curl -fsSL -o /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
  chmod +x /usr/local/bin/kind
fi

echo "Devcontainer ready. To start local Kubernetes:"
echo "  kind create cluster --name sentinel-weave"

