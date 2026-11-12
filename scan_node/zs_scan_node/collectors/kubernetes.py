"""Kubernetes over the read-only API with a static token or client certificate.

* kubeconfig ``exec``/``auth-provider`` plugins and ``insecure-skip-tls-verify`` are refused; the API server
  certificate is always verified against ``ca_pem`` (if set) or the kubeconfig's certificate-authority-data.
* Secrets are read only at Tier 2 and only with ``fieldSelector=type=kubernetes.io/tls`` (other secrets' values are
  never fetched).  From each TLS secret only ``tls.crt`` is parsed; ``tls.key`` is dropped unread.
* 403 on a resource becomes a ``denied`` coverage row; 404 on a CRD becomes ``not_installed``.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import ssl
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml

from zs_scan_node import tlsprobe as T
from zs_scan_node.certparse import cert_facts, key_facts, load_certs
from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import JobContext, register_asset_types
from zs_scan_node.netutil import Blocked, http_client, is_ip, resolve_checked

PAGE = 200
MAX_ITEMS = 5000
MAX_PAGES = MAX_ITEMS // PAGE + 20  # a server that keeps sending "continue" cannot keep the job forever
MAX_BODY = 32 * 1024 * 1024  # bytes per API response
ISTIO_ROOT_NAMESPACE = "istio-system"  # meshConfig.rootNamespace default: its selector-less policy is mesh-wide
# Linkerd policy resources (policy.linkerd.io) at the versions Linkerd 2.16+ serves; API discovery picks the versions
# the cluster actually serves (Server was v1beta1/v1beta2 before).  CRDs: linkerd-crds chart, templates/policy/.
LINKERD_RESOURCES = {
    "servers": "/apis/policy.linkerd.io/v1beta3/servers",
    "serverauthorizations": "/apis/policy.linkerd.io/v1beta1/serverauthorizations",
    "authorizationpolicies": "/apis/policy.linkerd.io/v1alpha1/authorizationpolicies",
    "meshtlsauthentications": "/apis/policy.linkerd.io/v1alpha1/meshtlsauthentications",
    "networkauthentications": "/apis/policy.linkerd.io/v1alpha1/networkauthentications",
}
LINKERD_TRUST_ROOTS = ("linkerd-identity-trust-roots", "ca-bundle.crt")  # ConfigMap and key with the trust anchors

register_asset_types("k8s_mesh_destination", "k8s_mesh_server")


class Api:
    def __init__(self, ctx: JobContext, config: dict, secrets: dict) -> None:
        self.ctx = ctx
        self.api_url = str(config.get("api_url") or "").rstrip("/")
        parts = urlsplit(self.api_url)
        if parts.scheme != "https" or not parts.hostname:
            raise ConfigError("api_url must be an https:// address")
        self.host, self.port = parts.hostname, parts.port or 443
        self._tmp = tempfile.mkdtemp(prefix="zsk8s-")
        os.chmod(self._tmp, 0o700)
        self.client: httpx.Client | None = None  # built by check_scope(), pinned to the address it checked
        try:
            self._ssl, self._headers = self._tls(config, secrets)
        except BaseException:
            shutil.rmtree(self._tmp, ignore_errors=True)
            raise

    def _tls(self, config: dict, secrets: dict) -> tuple[ssl.SSLContext, dict[str, str]]:
        text = secrets.get("kubeconfig")
        if config.get("credential_type") == "vault":
            from zs_scan_node import vault

            ref = config.get("vault") or {}
            fetched = vault.fetch(str(ref.get("provider")), str(ref.get("path") or ""), self.ctx.vault_prefix)
            text = fetched.get("kubeconfig") or text
            for v in fetched.values():
                self.ctx.scrubber.add(v)
        if not text:
            raise ConfigError("no kubeconfig is stored for this cluster")
        try:
            kc = yaml.safe_load(text)
        except yaml.YAMLError:
            raise ConfigError("the kubeconfig is not valid YAML") from None
        if not isinstance(kc, dict):
            raise ConfigError("the kubeconfig is not a mapping")
        ctx_name = config.get("context") or kc.get("current-context")
        contexts = {c.get("name"): c.get("context") or {} for c in kc.get("contexts") or [] if isinstance(c, dict)}
        context = contexts.get(ctx_name) or (next(iter(contexts.values())) if contexts else {})
        clusters = {c.get("name"): c.get("cluster") or {} for c in kc.get("clusters") or [] if isinstance(c, dict)}
        users = {u.get("name"): u.get("user") or {} for u in kc.get("users") or [] if isinstance(u, dict)}
        cluster = clusters.get(context.get("cluster")) or (next(iter(clusters.values())) if clusters else {})
        user = users.get(context.get("user")) or (next(iter(users.values())) if users else {})
        if cluster.get("insecure-skip-tls-verify"):
            raise ConfigError("the kubeconfig disables certificate checks (insecure-skip-tls-verify); remove it")
        if "exec" in user or "auth-provider" in user:
            raise ConfigError("the kubeconfig uses an exec or auth-provider plugin; use a service-account token")
        ca_text = config.get("ca_pem")
        if not ca_text and cluster.get("certificate-authority-data"):
            ca_text = base64.b64decode(cluster["certificate-authority-data"]).decode("ascii", "replace")
        sslctx = ssl.create_default_context(cadata=ca_text) if ca_text else ssl.create_default_context()
        headers = {"Accept": "application/json", "User-Agent": "zeroshield-scan-node"}
        if user.get("token"):
            self.ctx.scrubber.add(user["token"])
            headers["Authorization"] = f"Bearer {user['token']}"
        elif user.get("client-certificate-data") and user.get("client-key-data"):
            cert = base64.b64decode(user["client-certificate-data"])
            key = base64.b64decode(user["client-key-data"])
            self.ctx.scrubber.add(key.decode("ascii", "replace"))
            cpath, kpath = os.path.join(self._tmp, "c.pem"), os.path.join(self._tmp, "k.pem")
            fd = os.open(kpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            with open(cpath, "wb") as f:
                f.write(cert)
            try:
                sslctx.load_cert_chain(cpath, kpath)
            finally:
                for p in (cpath, kpath):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        else:
            raise ConfigError("the kubeconfig user has neither a token nor client certificate data")
        return sslctx, headers

    def check_scope(self) -> str:
        """Resolve the API server once, apply never-scan, and pin the HTTP client to the checked address (the
        certificate is still checked against the name in api_url)."""
        try:
            ip = resolve_checked(self.host, self.ctx.never_scan)[0]
        except Blocked as exc:
            raise _Skip("skipped_never_scan", str(exc)) from None
        except OSError:
            raise ConfigError(f"could not resolve {self.host}") from None
        if self.client is not None:
            self.client.close()
        self.client = http_client(self.api_url, ip, self.ctx.never_scan, verify=self._ssl, headers=self._headers,
                                  timeout=20.0)
        return ip

    def get(self, path: str, params: dict | None = None) -> tuple[int, Any]:
        if self.client is None:
            raise _Fail("error", "internal: the API server address was not checked before use")
        try:
            with self.client.stream("GET", path, params=params) as r:
                status, raw, size = r.status_code, bytearray(), 0
                for chunk in r.iter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY:
                        raise _TooLarge("error", f"the API server answered {path} with more than {MAX_BODY // 2**20} MB")
                    stop = self.ctx.should_stop()
                    if stop:
                        raise _Skip(stop)
                    raw += chunk
        except Blocked as exc:  # the API server's address was listed while the job ran
            raise _Skip("skipped_never_scan", str(exc)) from None
        except httpx.ConnectError as exc:
            msg = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate" in msg.lower():
                raise ConfigError("the API server certificate is not trusted by the CA you gave, or does not match "
                                  "the address in api_url") from None
            raise _Fail("unreachable", exc.__class__.__name__) from None
        except httpx.TimeoutException:
            raise _Fail("timeout", "the API server did not answer") from None
        except httpx.HTTPError as exc:
            raise _Fail("error", exc.__class__.__name__) from None
        try:
            body = json.loads(bytes(raw))
        except ValueError:
            body = None
        return status, body

    def post(self, path: str, body: dict) -> tuple[int, Any]:
        if self.client is None:
            return 0, {"error": "not checked"}
        try:
            r = self.client.post(path, json=body)
            return r.status_code, r.json()
        except Blocked as exc:
            raise _Skip("skipped_never_scan", str(exc)) from None
        except (httpx.HTTPError, ValueError) as exc:
            return 0, {"error": exc.__class__.__name__}

    def list_all(self, path: str, params: dict | None = None):
        """Yield items across pages; returns early with ('denied'|'not_installed', None) on 403/404."""
        cont = None
        count = 0
        pages = 0
        while True:
            stop = self.ctx.should_stop()
            if stop:
                raise _Skip(stop)
            pages += 1
            if pages > MAX_PAGES:
                yield ("truncated", None)
                return
            p = dict(params or {})
            p["limit"] = PAGE
            if cont:
                p["continue"] = cont
            try:
                status, body = self.get(path, p)
            except _TooLarge as big:  # one oversized page costs this resource, not the rest of the cluster
                yield ("error", big.error)
                return
            if status in (401,):
                raise _Fail("auth_failed", "the API server refused the credential")
            if status == 403:
                yield ("denied", None)
                return
            if status == 404:
                yield ("not_installed", None)
                return
            if status != 200 or not isinstance(body, dict):
                yield ("error", f"HTTP {status}")
                return
            for item in body.get("items") or []:
                yield ("item", item)
                count += 1
                if count >= MAX_ITEMS:
                    yield ("truncated", None)
                    return
            cont = (body.get("metadata") or {}).get("continue")
            if not cont:
                return

    def close(self) -> None:
        try:
            if self.client is not None:
                self.client.close()
        finally:
            shutil.rmtree(self._tmp, ignore_errors=True)


class _Fail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


class _TooLarge(_Fail):
    pass


class _Skip(Exception):
    def __init__(self, status: str, detail: str | None = None) -> None:
        super().__init__(detail or status)
        self.status, self.detail = status, detail


_PEM_KEY = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY)-----.*?-----END \1-----", re.S)


def embedded_private_keys(text: str) -> list[dict[str, Any]]:
    """Private keys pasted into text (ConfigMap values): type and size only.  The key is parsed in memory to read
    its public half and then dropped; nothing but these facts leaves the node."""
    out = []
    for m in _PEM_KEY.finditer(text):
        block = "\n".join(line.strip() for line in m.group(0).splitlines() if line.strip())
        facts: dict[str, Any] = {"pem_type": m.group(1), "encrypted": "ENCRYPTED" in m.group(1)}
        try:
            from cryptography.hazmat.primitives import serialization

            if m.group(1) == "OPENSSH PRIVATE KEY":
                key = serialization.load_ssh_private_key(block.encode(), password=None)
            else:
                key = serialization.load_pem_private_key(block.encode(), password=None)
            facts.update(key_facts(key.public_key()))
        except Exception:
            facts["parsed"] = False
        out.append(facts)
        if len(out) >= 20:
            break
    return out


def _meta(item: dict) -> tuple[str, str]:
    m = item.get("metadata") or {}
    return str(m.get("namespace") or ""), str(m.get("name") or "")


# ----------------------------------------------------------------------------- service mesh
def istio_root_namespace(item: dict) -> str | None:
    """meshConfig.rootNamespace from an Istio mesh ConfigMap ('istio' or 'istio-<revision>', key 'mesh'); a mesh
    config without it means the namespace istiod runs in (Istio's default)."""
    ns, name = _meta(item)
    mesh = (item.get("data") or {}).get("mesh")
    if not (name == "istio" or name.startswith("istio-")) or not isinstance(mesh, str):
        return None
    try:
        cfg = yaml.safe_load(mesh)
    except yaml.YAMLError:
        return None
    if cfg is None:
        return ns or None
    if not isinstance(cfg, dict):
        return None
    root = cfg.get("rootNamespace")
    return str(root) if isinstance(root, str) and root else (ns or None)


def peer_authentication_facts(item: dict, roots: set[str]) -> dict[str, Any]:
    ns, name = _meta(item)
    spec = item.get("spec") or {}
    mode = str((spec.get("mtls") or {}).get("mode") or "UNSET").upper()
    # UNSET inherits from the namespace / mesh-wide policy; on the mesh-wide policy (root namespace, no
    # selector) Istio then applies PERMISSIVE, so the classifier needs the policy's scope.
    selector = (spec.get("selector") or {}).get("matchLabels")
    scope_ = "workload" if selector else ("mesh" if ns in roots else "namespace")
    ports = {str(p): str((v or {}).get("mode") or "UNSET").upper()
             for p, v in list((spec.get("portLevelMtls") or {}).items())[:50] if isinstance(v, dict)}
    return {"namespace": ns, "name": name, "mtls_mode": mode, "scope": scope_, "port_modes": ports}


def destination_rule_facts(item: dict) -> dict[str, Any]:
    """TLS settings of an Istio DestinationRule (networking.istio.io): trafficPolicy.tls.mode for the host, each
    portLevelSettings entry and each subset (DISABLE / SIMPLE / MUTUAL / ISTIO_MUTUAL).  Certificate paths and
    credential names are not kept."""
    ns, name = _meta(item)
    spec = item.get("spec") or {}

    def tls_of(policy: Any) -> dict:
        return ((policy or {}).get("tls") or {}) if isinstance(policy, dict) else {}

    def mode(policy: Any) -> str | None:
        value = tls_of(policy).get("mode")
        return str(value).upper() if value else None

    top = spec.get("trafficPolicy") or {}
    policies = [top]
    ports: dict[str, str] = {}
    for pls in (top.get("portLevelSettings") or [])[:50]:
        if isinstance(pls, dict):
            policies.append(pls)
            if mode(pls):
                ports[str((pls.get("port") or {}).get("number"))] = mode(pls)
    subsets: dict[str, str] = {}
    for sub in (spec.get("subsets") or [])[:50]:
        if not isinstance(sub, dict):
            continue
        stp = sub.get("trafficPolicy") or {}
        policies.append(stp)
        if mode(stp):
            subsets[str(sub.get("name"))] = mode(stp)
        for pls in (stp.get("portLevelSettings") or [])[:50] if isinstance(stp, dict) else []:
            if isinstance(pls, dict):
                policies.append(pls)
                if mode(pls):
                    subsets[f"{sub.get('name')}:{(pls.get('port') or {}).get('number')}"] = mode(pls)
    return {"namespace": ns, "name": name, "host": spec.get("host"), "tls_mode": mode(top), "port_tls_modes": ports,
            "subset_tls_modes": subsets,
            "insecure_skip_verify": any(tls_of(p).get("insecureSkipVerify") is True for p in policies)}


def _istio(api: "Api", ctx: JobContext, loc: str, config_roots: set[str]) -> int:
    """config_roots: root namespaces read from Istio mesh ConfigMaps (empty when none was found)."""
    roots = set(config_roots) or {ISTIO_ROOT_NAMESPACE}
    n, listed, mesh_wide = 0, True, False
    for kind, item in api.list_all("/apis/security.istio.io/v1beta1/peerauthentications"):
        if kind != "item":  # not_installed (404), denied, error, truncated: the list is not complete
            listed = False
            ctx.coverage(loc, "istio peer authentication", kind, "", once=False)
            continue
        ns, name = _meta(item)
        facts = peer_authentication_facts(item, roots)
        mesh_wide = mesh_wide or facts["scope"] == "mesh"
        ctx.emit("k8s_mesh_policy", loc, f"{ns}/peerauthentication/{name}", name=f"{ns}/{name}", protocol="mtls",
                 facts=facts)
        n += 1
    if listed and config_roots and not mesh_wide:
        # Istio is installed (its mesh ConfigMap exists), the full list was read and no mesh-wide PeerAuthentication
        # exists: Istio applies PERMISSIVE mesh-wide by default
        root = sorted(roots)[0]
        ctx.emit("k8s_mesh_policy", loc, f"{root}/peerauthentication/(mesh default)", name=f"{root}/(mesh default)",
                 protocol="mtls", facts={"namespace": root, "name": None, "mtls_mode": "UNSET", "scope": "mesh",
                                         "port_modes": {}, "implicit": True})
        n += 1
    for kind, item in api.list_all("/apis/networking.istio.io/v1beta1/destinationrules"):
        if kind != "item":
            ctx.coverage(loc, "istio destination rules", kind, "", once=False)
            continue
        ns, name = _meta(item)
        ctx.emit("k8s_mesh_destination", loc, f"{ns}/destinationrule/{name}", name=f"{ns}/{name}", protocol="mtls",
                 facts=destination_rule_facts(item))
        n += 1
    return n


def _selector_matches(selector: Any, labels: dict) -> bool:
    if not isinstance(selector, dict):
        return False
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for expr in selector.get("matchExpressions") or []:
        if not isinstance(expr, dict):
            return False
        key, op, values = expr.get("key"), expr.get("operator"), expr.get("values") or []
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and labels.get(key) in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def linkerd_server_facts(items: dict[str, list[dict]]) -> list[dict[str, Any]]:
    """One row per Linkerd Server: whether clients without a mesh identity are allowed, and why.
    Unauthenticated when accessPolicy is all-/cluster-unauthenticated, when a ServerAuthorization targeting it sets
    client.unauthenticated, or when an AuthorizationPolicy targeting it (or its namespace) requires no
    MeshTLSAuthentication / ServiceAccount.  An AuthorizationPolicy whose referenced authentication does not exist
    is ignored by Linkerd, and so here."""
    present = {kind: {_meta(i) for i in items.get(kind) or []} for kind in ("meshtlsauthentications",
                                                                             "networkauthentications")}
    rows = []
    for server in (items.get("servers") or [])[:2000]:
        ns, name = _meta(server)
        spec = server.get("spec") or {}
        labels = (server.get("metadata") or {}).get("labels") or {}
        access = str(spec.get("accessPolicy") or "deny")
        reasons = []
        if access in ("all-unauthenticated", "cluster-unauthenticated"):
            reasons.append(f"accessPolicy {access}")
        for sa in items.get("serverauthorizations") or []:
            sns, sname = _meta(sa)
            sspec = sa.get("spec") or {}
            target = sspec.get("server") or {}
            if sns != ns or not (target.get("name") == name or _selector_matches(target.get("selector"), labels)):
                continue
            client = sspec.get("client") or {}
            if client.get("unauthenticated") is True:
                nets = [str((n or {}).get("cidr")) for n in client.get("networks") or [] if isinstance(n, dict)]
                reasons.append(f"ServerAuthorization {sname} allows unauthenticated clients"
                               + (f" from {', '.join(nets[:3])}" if nets else ""))
        for ap in items.get("authorizationpolicies") or []:
            ans, aname = _meta(ap)
            aspec = ap.get("spec") or {}
            ref = aspec.get("targetRef") or {}
            if ans != ns or not ((ref.get("kind") == "Server" and ref.get("name") == name)
                                 or (ref.get("kind") == "Namespace" and ref.get("name") == ns)):
                continue
            kinds, missing = [], False
            for auth in aspec.get("requiredAuthenticationRefs") or []:
                if not isinstance(auth, dict):
                    continue
                akind, rns = auth.get("kind"), auth.get("namespace") or ns
                table = {"MeshTLSAuthentication": "meshtlsauthentications",
                         "NetworkAuthentication": "networkauthentications"}.get(akind)
                if table and (rns, auth.get("name")) not in present[table]:
                    missing = True
                kinds.append(akind)
            if missing:
                continue
            if not any(k in ("MeshTLSAuthentication", "ServiceAccount") for k in kinds):
                reasons.append(f"AuthorizationPolicy {aname} requires no mesh identity"
                               + (" (network only)" if kinds else " (no authentication)"))
        rows.append({"mesh": "linkerd", "namespace": ns, "name": name, "port": spec.get("port"),
                     "access_policy": access, "proxy_protocol": spec.get("proxyProtocol"),
                     "unauthenticated": bool(reasons), "unauthenticated_by": reasons[:10]})
    return rows


def _linkerd_paths(api: "Api") -> dict[str, str] | None:
    """List paths for the Linkerd policy resources at the versions the cluster serves (API discovery), or None
    when policy.linkerd.io is not installed."""
    status, body = api.get("/apis/policy.linkerd.io")
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("versions"), list):
        return None
    versions = [str(v.get("version")) for v in body["versions"] if isinstance(v, dict) and v.get("version")]
    preferred = (body.get("preferredVersion") or {}).get("version") if isinstance(body.get("preferredVersion"), dict) else None
    order = ([preferred] if preferred in versions else []) + [v for v in versions if v != preferred]
    served: dict[str, str] = {}
    for version in order[:8]:
        if not re.fullmatch(r"v[0-9a-z]{1,16}", version):
            continue
        st, res = api.get(f"/apis/policy.linkerd.io/{version}")
        if st != 200 or not isinstance(res, dict):
            continue
        for r in res.get("resources") or []:
            rname = r.get("name") if isinstance(r, dict) else None
            if rname in LINKERD_RESOURCES and rname not in served:
                served[rname] = version
    return {r: f"/apis/policy.linkerd.io/{v}/{r}" for r, v in served.items()}


def _linkerd(api: "Api", ctx: JobContext, loc: str) -> int:
    paths = _linkerd_paths(api)
    if not paths or "servers" not in paths:
        ctx.coverage(loc, "linkerd policy", "not_installed", "", once=False)
        return 0
    items: dict[str, list[dict]] = {}
    for resource, path in paths.items():
        items[resource] = []
        for kind, item in api.list_all(path):
            if kind != "item":
                ctx.coverage(loc, f"linkerd {resource}", kind, "", once=False)
                continue
            items[resource].append(item)
    rows = linkerd_server_facts(items)
    for facts in rows:
        ctx.emit("k8s_mesh_server", loc, f"{facts['namespace']}/server/{facts['name']}",
                 name=f"{facts['namespace']}/{facts['name']}", protocol="mtls", facts=facts)
    return len(rows)


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    api = Api(ctx, config, secrets)
    loc = api.api_url
    n = 0
    try:
        try:
            ip = api.check_scope()
        except _Skip as skip:
            ctx.outcome(loc, skip.status, skip.detail, started=started)
            return skip.detail or "API server is on the never-scan list"
        status, version = api.get("/version")
        if status == 401:
            raise _Fail("auth_failed", "the API server refused the credential")
        if status != 200:
            raise _Fail("error", f"/version answered HTTP {status}")
        cluster: dict[str, Any] = {"version": (version or {}).get("gitVersion"), "platform": (version or {}).get("platform"),
                                   "tier": int(config.get("tier") or 1), "managed": bool(config.get("managed"))}
        nodes = []
        for kind, item in api.list_all("/api/v1/nodes"):
            if kind != "item":
                ctx.coverage(loc, "nodes", kind, "")
                continue
            info = (item.get("status") or {}).get("nodeInfo") or {}
            nodes.append({"name": _meta(item)[1], "kubelet": info.get("kubeletVersion"), "os": info.get("osImage"),
                          "kernel": info.get("kernelVersion"), "runtime": info.get("containerRuntimeVersion")})
        cluster["nodes"] = nodes[:200]
        cluster["node_count"] = len(nodes)
        # API server TLS (one full handshake + legacy version probes)
        fh = T.s_client(ip, api.port, "tls", api.host if not is_ip(api.host) else None) if T.have_openssl() else None
        if fh is not None and fh.ok:
            versions = {}
            for v in (T.TLS10, T.TLS11):
                try:
                    r = T.probe(ip, api.port, "tls", T.build_client_hello(v, T.LEGACY_SUITES), 8.0)
                    versions[T.VERSION_NAMES[v]] = bool(r.ok and r.version == v)
                except (T.ProbeError, T.StarttlsUnavailable):
                    versions[T.VERSION_NAMES[v]] = None
            versions[fh.version or "?"] = True
            ctx.emit("tls_endpoint", loc, f"{ip}:{api.port}", name="Kubernetes API server", algorithm=fh.cipher,
                     protocol=fh.version, facts={"service": "kubernetes-api", "negotiated_version": fh.version,
                                                 "negotiated_cipher": fh.cipher, "negotiated_group": fh.group,
                                                 "peer_signature_type": fh.peer_sig_type, "versions": versions})
            n += 1
            for i, der in enumerate(fh.certs_der[:10]):
                for cert in load_certs(der):
                    f = cert_facts(cert, "tls")
                    ctx.emit("certificate", loc, f"{ip}:{api.port}#chain[{i}]", name=f.get("subject", ""),
                             algorithm=f.get("key_alg"), key_size=f.get("key_size"), facts={**f, "chain_index": i,
                                                                                          "role": "kubernetes-api"})
                    n += 1
        ctx.emit("k8s_cluster", loc, loc, name=str(cluster.get("version") or "cluster"), facts=cluster)
        n += 1
        # ingress TLS
        for kind, item in api.list_all("/apis/networking.k8s.io/v1/ingresses"):
            if kind != "item":
                ctx.coverage(loc, "ingresses", kind, "")
                continue
            ns, name = _meta(item)
            for i, tls in enumerate((item.get("spec") or {}).get("tls") or []):
                ctx.emit("k8s_ingress_tls", loc, f"{ns}/ingress/{name}#tls[{i}]", name=f"{ns}/{name}",
                         facts={"namespace": ns, "ingress": name, "hosts": (tls.get("hosts") or [])[:50],
                                "secret": tls.get("secretName")})
                n += 1
        # cert-manager Certificates
        for kind, item in api.list_all("/apis/cert-manager.io/v1/certificates"):
            if kind != "item":
                ctx.coverage(loc, "cert-manager certificates", kind, "")
                continue
            ns, name = _meta(item)
            spec, st = item.get("spec") or {}, item.get("status") or {}
            pk = spec.get("privateKey") or {}
            alg = pk.get("algorithm") or "RSA"
            size = pk.get("size") or (2048 if alg == "RSA" else 256 if alg == "ECDSA" else None)
            ctx.emit("k8s_certificate", loc, f"{ns}/certificate/{name}", name=f"{ns}/{name}", algorithm=alg, key_size=size,
                     facts={"namespace": ns, "name": name, "dns_names": (spec.get("dnsNames") or [])[:50],
                            "issuer": (spec.get("issuerRef") or {}).get("name"),
                            "issuer_kind": (spec.get("issuerRef") or {}).get("kind"),
                            "rotation_policy": pk.get("rotationPolicy"), "encoding": pk.get("encoding"),
                            "not_after": st.get("notAfter"), "renewal_time": st.get("renewalTime"),
                            "secret": spec.get("secretName"), "duration": spec.get("duration")})
            n += 1
        # ConfigMaps: CA bundles (public certificates) and private keys that should not be there; also the Istio mesh
        # config (rootNamespace) and the Linkerd trust anchors, which the mesh checks below need
        cm_rows = 0
        istio_roots: set[str] = set()
        for kind, item in api.list_all("/api/v1/configmaps"):
            if kind != "item":
                ctx.coverage(loc, "configmaps", kind, "")
                continue
            ns, name = _meta(item)
            root = istio_root_namespace(item)
            if root:
                istio_roots.add(root)
            for key, value in ((item.get("data") or {}).items()):
                if not isinstance(value, str) or cm_rows >= 500:
                    continue
                where = f"{ns}/configmap/{name}#{key}"
                if "-----BEGIN CERTIFICATE-----" in value:
                    role = {"role": "linkerd-trust-root"} if (name, key) == LINKERD_TRUST_ROOTS else {}
                    for i, cert in enumerate(load_certs(value.encode())[:50]):
                        f = cert_facts(cert, "k8s")
                        ctx.emit("certificate", loc, where if i == 0 else f"{where}[{i}]", name=f.get("subject", ""),
                                 algorithm=f.get("key_alg"), key_size=f.get("key_size"),
                                 facts={**f, "configmap": f"{ns}/{name}", "key": key, **role})
                        n += 1
                        cm_rows += 1
                for pk in embedded_private_keys(value):
                    ctx.emit("private_key", loc, where, name=f"private key in ConfigMap {ns}/{name}",
                             algorithm=pk.get("key_alg"), key_size=pk.get("key_size"),
                             facts={**pk, "configmap": f"{ns}/{name}", "key": key, "plaintext_in_configmap": True})
                    n += 1
                    cm_rows += 1
        # Istio mTLS: PeerAuthentications (security.istio.io), the mesh-wide default, DestinationRules
        # (networking.istio.io); then Linkerd policy (policy.linkerd.io)
        n += _istio(api, ctx, loc, istio_roots)
        n += _linkerd(api, ctx, loc)
        # Tier 2: TLS secrets only
        if int(config.get("tier") or 1) >= 2:
            for kind, item in api.list_all("/api/v1/secrets", {"fieldSelector": "type=kubernetes.io/tls"}):
                if kind != "item":
                    ctx.coverage(loc, "TLS secrets", kind, "the role cannot list secrets" if kind == "denied" else "")
                    continue
                ns, name = _meta(item)
                data = item.get("data") or {}
                data.pop("tls.key", None)  # never parsed, never kept
                crt = data.get("tls.crt")
                certs = []
                if isinstance(crt, str):
                    try:
                        certs = load_certs(base64.b64decode(crt))
                    except Exception:
                        certs = []
                if not certs:
                    ctx.emit("k8s_tls_secret", loc, f"{ns}/secret/{name}", name=f"{ns}/{name}",
                             facts={"namespace": ns, "name": name, "parsed": False})
                    n += 1
                    continue
                f = cert_facts(certs[0], "k8s")
                ctx.emit("k8s_tls_secret", loc, f"{ns}/secret/{name}", name=f"{ns}/{name}", algorithm=f.get("key_alg"),
                         key_size=f.get("key_size"), facts={**f, "namespace": ns, "secret": name,
                                                            "chain_length": len(certs)})
                n += 1
        else:
            ctx.coverage(loc, "TLS secrets", "not_supported", "Tier 1 does not read Secrets; use Tier 2", once=True)
        ctx.outcome(loc, "ok", started=started, assets=n)
        return f"{n} assets from {loc}"
    except _Fail as fail:
        ctx.outcome(loc, fail.status, fail.error, started=started, assets=n)
        return fail.error
    except _Skip as skip:  # cancelled, window closed or deadline reached between pages, or the address was listed
        ctx.outcome(loc, skip.status, skip.detail, started=started, assets=n)
        return f"stopped ({skip.status}) after {n} assets"
    finally:
        api.close()


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    sample = {"target": str(config.get("api_url") or ""), "status": "ready", "reachable": False, "login": False,
              "privilege": None, "note": ""}
    try:
        api = Api(ctx, config, secrets)
    except ConfigError as exc:
        sample.update(status="error", note=str(exc))
        ctx.samples.append(sample)
        return str(exc)
    try:
        api.check_scope()
        status, version = api.get("/version")
        sample["reachable"] = True
        if status == 401:
            sample.update(status="auth_failed", note="the API server refused the credential")
        elif status != 200:
            sample.update(status="error", note=f"/version answered HTTP {status}")
        else:
            st, body = api.get("/api/v1/namespaces", {"limit": 1})
            sample["login"] = st == 200
            if st == 403:
                sample.update(status="auth_failed", note="the credential cannot list namespaces (bind zs-cbom-tier1)")
            elif int(config.get("tier") or 1) >= 2:
                st, review = api.post("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", {
                    "apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
                    "spec": {"resourceAttributes": {"verb": "list", "resource": "secrets"}}})
                allowed = bool(((review or {}).get("status") or {}).get("allowed"))
                sample["privilege"] = allowed
                if not allowed:
                    sample.update(status="rbac_denied", note="Tier 2 needs list on secrets: bind the zs-cbom-tier2 ClusterRole")
            if sample["status"] == "ready":
                sample["note"] = f"Kubernetes {(version or {}).get('gitVersion')}"
    except ConfigError as exc:
        sample.update(status="error", note=str(exc))
    except _Skip as skip:
        sample.update(status=skip.status, note=skip.detail or ("the API server address is on the never-scan list"
                      if skip.status == "skipped_never_scan" else "the test was stopped"))
    except _Fail as fail:
        sample.update(status=fail.status, note=fail.error)
    finally:
        api.close()
    ctx.samples.append(sample)
    return sample["note"]
