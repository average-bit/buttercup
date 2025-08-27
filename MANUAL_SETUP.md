# Manual Setup Guide

This guide provides detailed manual setup instructions for the Buttercup CRS system. If you prefer automated setup, use `make setup-local` instead.

## Prerequisites

Before starting manual setup, ensure you have the following dependencies installed:

### System Packages

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y make curl git

# RHEL/CentOS/Fedora  
sudo yum install -y make curl git
# or
sudo dnf install -y make curl git

# MacOS
brew install make curl git
```

### Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

### Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### k3s

`k3s` is a lightweight Kubernetes distribution that will be used for local deployment. It also includes `kubectl`.

```bash
curl -sfL https://get.k3s.io | sh -
# Make kubeconfig readable by the current user
sudo chmod 644 /etc/rancher/k3s/k3s.yaml
```

### Git LFS (for some tests)

```bash
sudo apt-get install git-lfs
git lfs install
```

## Manual Configuration

1. **Create configuration file:**

```bash
cp deployment/env.template deployment/env
```

2. **Configure the environment file** (`deployment/env`):

Look at the comments in the `deployment/env.template` for how to set variables.

### External SigNoz Configuration

If you want to use an external SigNoz instance instead of the default local deployment, you can configure custom OpenTelemetry settings:

1. **Disable local SigNoz deployment:**
```bash
# In deployment/env
export DEPLOY_SIGNOZ=false
```

2. **Configure external OTEL endpoint:**
```bash
# In deployment/env
export OTEL_ENDPOINT="https://your-signoz-instance.com"
export OTEL_PROTOCOL="http"  # or "grpc"
export OTEL_TOKEN="your-otel-token"  # optional
```

## Start Services Manually

```bash
# Start services manually
cd deployment && make up

# Port forward manually
kubectl port-forward -n crs service/buttercup-ui 31323:1323

# Test manually
./orchestrator/scripts/task_crs.sh
```

## Verification

After setup, verify your installation by running:

```bash
make status
```

## Troubleshooting

### Common Manual Setup Issues

1. **Docker permission issues:**

```bash
sudo usermod -aG docker $USER
# Log out and back in
```

2. **k3s won't start:**

```bash
# Check the k3s service status
sudo systemctl status k3s

# Restart the k3s service
sudo systemctl restart k3s
```

3. **Helm chart issues:**

```bash
helm repo update
helm dependency update deployment/k8s/
```

For additional troubleshooting, see the [Quick Reference Guide](QUICK_REFERENCE.md).