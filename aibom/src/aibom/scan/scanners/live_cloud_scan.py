"""Level-5 scanner: live cloud sweep -> deployed AI resources.

Queries a cloud account for live AI resources (Bedrock models, SageMaker
endpoints, Vertex models, Azure deployments) via an INJECTABLE client, so:

* in production a real provider client (boto3, google-cloud-aiplatform, …) is
  supplied;
* in tests the **provider client is mocked**, NEVER the scanner — the scanner is
  the unit under test (skill-testing-anti-patterns).

The client exposes one synchronous method ``list_ai_resources() ->
list[dict{ref,name,vendor,kind?}]``. The scan awaits that terminal result; it
never sleeps/polls. With no client set, the scanner is a no-op (no credentials).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from aibom.model.component import CloudServiceComponent
from aibom.scan.registry import ScanContext, Scanner, register


@register
class LiveCloudScanner(Scanner):
    name = "live-cloud"
    level = 5
    order = 33

    #: Injectable provider-client factory. Production wiring or a test sets this;
    #: ``None`` means no credentials -> the live sweep is skipped. Read off the
    #: CLASS (``type(self)``), never ``self.`` — a plain-function factory assigned
    #: here would otherwise bind as a method and receive ``self`` as an argument.
    client_factory: ClassVar[Callable[[], Any] | None] = None

    def matches(self, root: Path) -> bool:
        # Independent of the filesystem: live sweep applies whenever a client is
        # configured (a directory is still required to anchor the scan).
        return type(self).client_factory is not None

    def scan(self, ctx: ScanContext) -> None:
        factory = type(self).client_factory
        if factory is None:
            return
        client = factory()
        for res in client.list_ai_resources():  # provider SDK call (mocked in tests)
            ref = str(res.get("ref") or f"cloud_service-{res['name']}")
            props = {"discovery:source": "live-cloud"}
            if res.get("region"):
                props["discovery:region"] = str(res["region"])
            ctx.add_component(
                CloudServiceComponent(
                    bom_ref=ref,
                    name=str(res["name"]),
                    publisher=str(res.get("vendor") or ""),
                    properties=props,
                )
            )


__all__ = ["LiveCloudScanner"]
