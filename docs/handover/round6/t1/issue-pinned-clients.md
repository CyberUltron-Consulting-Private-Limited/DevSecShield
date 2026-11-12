**Found by:** the state-propagation review of the #17 fix (branch `fix/never-scan-dual-stack`). This gap was already there before #17 and is separate from it.

**What happens:** `netutil.http_client(url, ip, never)` checks `ip` against the never-scan list once, when the client is built. The pinned transport (`_Pinned.handle_request`) only sets the SNI name and does not check the list again. Collectors build one client and reuse it for the whole session:
- `container_images.Registry._client` caches one client for each origin (registry, token service, blob redirect). A pull reuses it for every manifest and every layer.
- `kubernetes.Api.check_scope` builds `self.client` once, and `Api.get` reuses it for every page of every resource.

So if a never-scan entry arrives through the heartbeat while one of these sessions runs, the node keeps sending requests to that address until the session ends. Today that means the end of the image, or the end of the Kubernetes collection. Socket collectors (`netutil.connect`, SSH, the network sweep) check the list again for every connection, so they do not have this gap.

**Expected:** "The never-scan list applies live", the same as for socket connections. A request to an address that has just been listed is refused and reported as `skipped_never_scan`.

**Possible fix:** call `checked_ip(ip, never)` in `_Pinned.handle_request` before each request, and map `Blocked` to `skipped_never_scan` where the collectors call `client.send` / `client.stream` (otherwise the outcome would be reported as `error`). Add a test that changes the list between two requests on one client.

**Severity:** minor. The window is one image pull or one cluster collection, and the address was in scope when the job started.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR
