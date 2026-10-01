# Reuse the workload image in Kubernetes

These complete workload manifests target an **existing, network-reachable, TLS-enabled Conjur installation**. They do not deploy Conjur/Postgres, migrate the Compose database, configure a Kubernetes authenticator, or provide an HA server. Provision the same policies and two host identities in that installation first. Do not reuse lab identities in production.

This handoff covers checkout/fraud only. The optional four tenant/environment message APIs currently run in Compose; their Kubernetes Deployments, TLS routing, scoped secret injection and NetworkPolicies are not provided. Do not infer tenant isolation from these base manifests.

1. Build and publish `app/` to your private registry, then set both Deployment images to its immutable digest. For a local cluster, load `conjur-sandbox-app:local` into the cluster's image store instead.
2. Create the namespace and endpoint/CA configuration. The endpoint must have a certificate trusted by the supplied CA, with a matching DNS name; `localhost` and the Compose hostname `proxy` are not Kubernetes endpoints.

```bash
kubectl create namespace conjur-lab --dry-run=client -o yaml | kubectl apply -f -
export CONJUR_APPLIANCE_URL=https://conjur.internal.example
export CONJUR_CA_FILE=/secure/path/conjur-ca.crt
kubectl -n conjur-lab create configmap conjur-endpoint \
  --from-literal=CONJUR_APPLIANCE_URL="$CONJUR_APPLIANCE_URL" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n conjur-lab create configmap conjur-ca \
  --from-file=tls.crt="$CONJUR_CA_FILE" --dry-run=client -o yaml | kubectl apply -f -
```

3. Supply each host's API key via a secure local file, not an argument value or a committed YAML document:

```bash
export CHECKOUT_KEY_FILE=/secure/path/checkout-api-key
export FRAUD_KEY_FILE=/secure/path/fraud-api-key
kubectl -n conjur-lab create secret generic checkout-identity \
  --from-file=api-key="$CHECKOUT_KEY_FILE"
kubectl -n conjur-lab create secret generic fraud-identity \
  --from-file=api-key="$FRAUD_KEY_FILE"
kubectl apply -f k8s/workloads.yml
kubectl -n conjur-lab rollout status deployment/checkout
kubectl -n conjur-lab rollout status deployment/fraud
kubectl -n conjur-lab port-forward service/checkout 8081:8080
```

`CONJUR_ACCOUNT` defaults to `sandbox`; change the ConfigMap for another account. Host paths and variable paths must match the policies. Kubernetes Secrets are not inherently encrypted: enable etcd encryption at rest, restrict RBAC, and prefer an external secret store or workload JWT/Kubernetes authentication for production. Secret volumes use group-readable mode for UID 10001; no `subPath` mounts are used. Account for token caches when revoking identities.

Services are cluster-internal. Add cluster-specific NetworkPolicies that allow DNS and only your Conjur HTTPS endpoint, and restrict inbound evaluation access to authorized callers. Readiness fails when Conjur is unavailable; liveness does not cause restart storms. The supplied namespace enforces the restricted Pod Security standard. This is a Kubernetes-ready workload handoff, not a production cluster security baseline.
