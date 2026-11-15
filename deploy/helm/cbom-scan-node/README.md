# cbom-scan-node Helm chart

Runs the ZeroShield CBOM scan node in Kubernetes. The command on **CBOM Sources > Scan nodes > Add scan node >
Helm chart** installs the Deployment; **Create agent pool token** gives the DaemonSet command.

The chart and the node image are downloads on the same page (**Download Helm chart**, **Download scan node image**:
`cbom-scan-node-<version>.tgz`, `scan-node-<version>.tar.gz` and its `.sha256`), served by your ZeroShield server.
Push the image to a registry your cluster pulls from, then install the downloaded chart. Set `ZS_API_URL` to **the
API URL shown in the Add scan node wizard** (the wizard's own command already has it, with your registration token).
Run it as one block: nothing is loaded, pushed or installed if the image file fails its SHA-256 check.

```sh
REGISTRY=registry.example.internal/zeroshield    # a registry your cluster can pull from
ZS_API_URL='<the API URL shown in the Add scan node wizard>'
sha256sum -c scan-node-1.0.1.tar.gz.sha256 && \
docker load -i scan-node-1.0.1.tar.gz && \
docker tag localhost/zeroshield/cbom-scan-node:1.0.1 "$REGISTRY/cbom-scan-node:1.0.1" && \
docker push "$REGISTRY/cbom-scan-node:1.0.1" && \
helm upgrade --install zs-scan-node ./cbom-scan-node-1.0.1.tgz \
  --namespace zs-cbom --create-namespace \
  --set image.repository="$REGISTRY/cbom-scan-node" --set image.tag='1.0.1' \
  --set apiUrl="$ZS_API_URL" --set registrationToken='zsr_...'
```

That installs an agentless node (it reaches your servers, clusters, databases and networks with the credentials you
store). Host agents (one pod per Kubernetes node, each reads only its own node and never gets a credential) use the
command that **Create agent pool token** shows, or, with the image pushed as above:

```sh
helm upgrade --install zs-host-agents ./cbom-scan-node-1.0.1.tgz \
  --namespace zs-cbom --create-namespace \
  --set image.repository="$REGISTRY/cbom-scan-node" --set image.tag='1.0.1' \
  --set apiUrl="$ZS_API_URL" \
  --set deployment.enabled=false --set agent.enabled=true --set agent.poolToken='zsp_...'
```

The image file loads as `localhost/zeroshield/cbom-scan-node:<version>`: `localhost/` is a registry host that never
resolves to a public registry, so nothing can be pulled under that name from the internet. It is also the chart's
default `image.repository`, as a placeholder: the chart refuses to render with it (a `helm install` that forgot
`--set image.repository=...` fails with that message) unless `image.pullPolicy=Never` (the image loaded on every node
by hand, e.g. `ctr -n k8s.io images import`). When your ZeroShield server names a public registry for the node
image, the wizard's command uses that image instead.

## What it creates

* **Secret** `<release>-tokens`: `registration-token` and/or `pool-token` (or bring your own with `existingSecret` /
  `agent.existingSecret`). The tokens are needed only until a node has enrolled. Each pod template carries a
  checksum of its token, so `helm upgrade` with a new token restarts the pods and they read it (with an
  `existingSecret`, run `kubectl rollout restart` after changing the Secret).
* **Deployment** (`deployment.enabled`, default on): 1 replica, `strategy: Recreate` (a node token and its signing key
  belong to exactly one process), uid/gid 10001, `fsGroup` 10001, `runAsNonRoot`, read-only root file system, all
  capabilities dropped, RuntimeDefault seccomp, no service-account token. State on the **PVC** `<release>-state`
  (`helm.sh/resource-policy: keep`, so an uninstall keeps the enrollment). A hostPath-backed PV needs its directory
  owned by uid 10001, since `fsGroup` does not apply to hostPath volumes.
* **DaemonSet** (`agent.enabled`): `ZS_MODE=agent`, `ZS_NODE_NAME` = the Kubernetes node name (downward API), the
  node's `/` mounted **read-only** at `/host` (`agent.hostRoot`; `recursiveReadOnly: IfPossible` on Kubernetes
  1.30+, which makes the host's submounts read-only too where the kubelet and the runtime support it), with
  `/host/proc`, `/host/sys`, `/host/dev` and `/host/run` hidden behind empty read-only mounts
  (`agent.hiddenHostPaths`): the agent never reads them, without recursive read-only mounts they would stay
  writable, and `/run` holds the container runtime's sockets. Per-node state on the host at `agent.statePath`
  (default `/var/lib/zs-node-agent/<namespace>.<release>`, one directory per release, so a restarted pod keeps its
  identity and two releases never share one). An init container with only `CAP_CHOWN`/`CAP_FOWNER` hands that
  directory to the agent's user. Tolerates every taint by default, so control-plane nodes are covered too.
  `agent.hostPID` shares the host PID namespace to read process libraries; `agent.runAsRoot` runs as uid 0 with only
  `CAP_DAC_READ_SEARCH` added to read root-only files; `agent.sysPtrace` (with both) adds `CAP_SYS_PTRACE`, which the
  kernel requires to read another user's `/proc/<pid>/maps` (it also allows attaching to any process on the node).
* **Pool nodes after a reset or delete**: a pod whose node is reset in ZeroShield gets a 401, enrolls again with
  the pool token and takes its node back (no enrollment used); a pod whose node is deleted enrolls as a new node
  (within the pool's cap). Once the pool token has expired or been revoked, such a pod waits, and enrolls as a new
  node once a new pool token is installed (`helm upgrade --set agent.poolToken=zsp_...`; delete the old, offline
  node in ZeroShield). To stop a node for good, keep its pod off that
  Kubernetes node (`agent.nodeSelector`) and delete the node in ZeroShield.

Both are ready while the node's heartbeat loop turns (the image health check: `$ZS_STATE_DIR/alive` younger than
180 s). There is no liveness probe: a node still waiting to enroll must not be restarted.

## Values

| Value | Default | |
|---|---|---|
| `image.repository`, `image.tag` | `localhost/zeroshield/cbom-scan-node` (the name the image file loads as), appVersion | |
| `apiUrl` | (required) | ZeroShield API URL (`https://`) |
| `registrationToken` / `existingSecret` | | Deployment enrollment |
| `httpsProxy`, `noProxy` | | outbound proxy to ZeroShield |
| `extraEnv` | `[]` | e.g. `ZS_VAULT_PATH_PREFIX`, `VAULT_ADDR`, `ZS_MAX_JOBS` |
| `persistence.size`, `.storageClass`, `.existingClaim` | `1Gi` | |
| `agent.enabled`, `agent.poolToken` / `agent.existingSecret` | `false` | DaemonSet of host agents |
| `agent.hostRoot`, `agent.hiddenHostPaths` | `/`, `[/proc, /sys, /dev, /run]` | each hidden path must exist on every node |
| `agent.statePath` | `/var/lib/zs-node-agent/<namespace>.<release>` | set it to keep the path of an earlier install |
| `agent.hostPID`, `agent.runAsRoot`, `agent.sysPtrace` | `false`, `false`, `false` | `sysPtrace` needs the other two |
| `allowInsecureHttp` | `false` | lab only: an `http://` apiUrl |
| `trust.caSecret` | | a Secret with `ca.pem`: a private CA for the ZeroShield API (`ZS_CA_FILE`) |
| `trust.clientSecret` | | a `kubernetes.io/tls` Secret: the node's client certificate when the API requires mTLS (`ZS_CLIENT_CERT` / `ZS_CLIENT_KEY`) |

### A private CA or an mTLS gateway in front of ZeroShield

Only for an on-prem ZeroShield or a gateway with its own CA or client-certificate check. Create the Secrets in the
release namespace from files on your machine (they never leave the cluster), then name them; the "Add scan node"
wizard writes these lines when you tick its trust options:

```sh
kubectl -n zs-cbom create secret generic zs-node-ca --from-file=ca.pem=/path/to/zeroshield-ca.pem
kubectl -n zs-cbom create secret tls zs-node-client --cert=/path/to/node.crt --key=/path/to/node.key
helm upgrade --install ... --set trust.caSecret=zs-node-ca --set trust.clientSecret=zs-node-client
```

The files are mounted read-only under `/etc/zs-node/trust`; the key is readable by the node's group only. The CA
replaces the default trust for the ZeroShield API only: your targets are checked as before.

## Proof

Installed with Helm v3.16.3 (`helm upgrade --install` with the wizard's `--set` flags, from this directory) on a
two-node k3s v1.31.4 cluster (server + agent, each in Docker): the Deployment enrolled (signed requests) and pulled
two images from a TLS registry with a private CA and vault-referenced Basic credentials (`libssl1.1 1.1.0j` in
`nginx:1.14` reported end of life with its purl); `helm upgrade --set agent.enabled=true` added the DaemonSet,
whose two pods enrolled with one pool token as `k3s-node-a` and `k3s-node-b` and each collected only its own node
(read-only `/host`; uid 10001; writes to `/host` refused); a deleted pod came back as the same node (no second
enrollment). Lab-only settings: `allowInsecureHttp=true` (plain-HTTP lab API), a static hostPath PV, and k3s's
containerd with `restrict_oom_score_adj = true` (the lab's Docker cannot raise pod OOM priority).

The round-5 review changes (token checksum annotations, `recursiveReadOnly`, `agent.hiddenHostPaths`, the
per-release `agent.statePath`, `agent.sysPtrace`) were rendered with Go text/template and sprig (Helm's engine
functions) and the manifests parsed and checked; they have not been installed on a cluster yet.
