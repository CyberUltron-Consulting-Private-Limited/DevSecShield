"""Kubernetes over the read-only API with a static token or client certificate.

* kubeconfig ``exec``/``auth-provider`` plugins and ``insecure-skip-tls-verify`` are refused; the API server
  certificate is always verified against ``ca_pem`` (if set) or the kubeconfig's certificate-authority-data.
* Secrets are read only at Tier 2 and only with ``fieldSelector=type=kubernetes.io/tls`` (other secrets' values are
  never fetched).  From each TLS secret only ``tls.crt`` is parsed; ``tls.key`` is dropped unread.
* 403 on a resource becomes a ``denied`` coverage row; 404 on a CRD becomes ``not_installed``.
"""
from __future__ import annotations

import base64
import ipaddress
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
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import resolve

PAGE = 200
MAX_ITEMS = 5000


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
        try:
            self.client = self._client(config, secrets)
        except BaseException:
            shutil.rmtree(self._tmp, ignore_errors=True)
            raise

    def _client(self, config: dict, secrets: dict) -> httpx.Client:
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
        return httpx.Client(base_url=self.api_url, verify=sslctx, headers=headers, timeout=20.0, follow_redirects=False,
                            trust_env=False)

    def check_scope(self) -> str:
        try:
            ips = [self.host] if _is_ip(self.host) else resolve(self.host)
        except OSError:
            raise ConfigError(f"could not resolve {self.host}") from None
        for ip in ips:
            if self.ctx.never_scan.blocks_ip(ip):
                raise _Skip("skipped_never_scan")
        return ips[0]

    def get(self, path: str, params: dict | None = None) -> tuple[int, Any]:
        try:
            r = self.client.get(path, params=params)
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
            body = r.json()
        except ValueError:
            body = None
        return r.status_code, body

    def post(self, path: str, body: dict) -> tuple[int, Any]:
        try:
            r = self.client.post(path, json=body)
            return r.status_code, r.json()
        except (httpx.HTTPError, ValueError) as exc:
            return 0, {"error": exc.__class__.__name__}

    def list_all(self, path: str, params: dict | None = None):
        """Yield items across pages; returns early with ('denied'|'not_installed', None) on 403/404."""
        cont = None
        count = 0
        while True:
            p = dict(params or {})
            p["limit"] = PAGE
            if cont:
                p["continue"] = cont
            status, body = self.get(path, p)
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
            self.client.close()
        finally:
            shutil.rmtree(self._tmp, ignore_errors=True)


class _Fail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


class _Skip(Exception):
    def __init__(self, status: str) -> None:
        super().__init__(status)
        self.status = status


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


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


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    api = Api(ctx, config, secrets)
    loc = api.api_url
    n = 0
    try:
        try:
            ip = api.check_scope()
        except _Skip as skip:
            ctx.outcome(loc, skip.status, started=started)
            return "API server is on the never-scan list"
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
        fh = T.s_client(ip, api.port, "tls", api.host if not _is_ip(api.host) else None) if T.have_openssl() else None
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
        # Istio mTLS
        for kind, item in api.list_all("/apis/security.istio.io/v1beta1/peerauthentications"):
            if kind != "item":
                ctx.coverage(loc, "istio peer authentication", kind, "", once=False)
                continue
            ns, name = _meta(item)
            mode = ((item.get("spec") or {}).get("mtls") or {}).get("mode") or "UNSET"
            ctx.emit("k8s_mesh_policy", loc, f"{ns}/peerauthentication/{name}", name=f"{ns}/{name}", protocol="mtls",
                     facts={"namespace": ns, "name": name, "mtls_mode": mode})
            n += 1
        # ConfigMaps: CA bundles (public certificates) and private keys that should not be there
        cm_rows = 0
        for kind, item in api.list_all("/api/v1/configmaps"):
            if kind != "item":
                ctx.coverage(loc, "configmaps", kind, "")
                continue
            ns, name = _meta(item)
            for key, value in ((item.get("data") or {}).items()):
                if not isinstance(value, str) or cm_rows >= 500:
                    continue
                where = f"{ns}/configmap/{name}#{key}"
                if "-----BEGIN CERTIFICATE-----" in value:
                    for i, cert in enumerate(load_certs(value.encode())[:50]):
                        f = cert_facts(cert, "k8s")
                        ctx.emit("certificate", loc, where if i == 0 else f"{where}[{i}]", name=f.get("subject", ""),
                                 algorithm=f.get("key_alg"), key_size=f.get("key_size"),
                                 facts={**f, "configmap": f"{ns}/{name}", "key": key})
                        n += 1
                        cm_rows += 1
                for pk in embedded_private_keys(value):
                    ctx.emit("private_key", loc, where, name=f"private key in ConfigMap {ns}/{name}",
                             algorithm=pk.get("key_alg"), key_size=pk.get("key_size"),
                             facts={**pk, "configmap": f"{ns}/{name}", "key": key, "plaintext_in_configmap": True})
                    n += 1
                    cm_rows += 1
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
    except _Skip:
        sample.update(status="skipped_never_scan", note="the API server address is on the never-scan list")
    except _Fail as fail:
        sample.update(status=fail.status, note=fail.error)
    finally:
        api.close()
    ctx.samples.append(sample)
    return sample["note"]
