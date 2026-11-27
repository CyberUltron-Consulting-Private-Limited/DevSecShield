import os
import tempfile

from langchain_core.documents import Document
from rich.console import Console

from helpers.agent.context import AuthRequirements
from helpers.agent.page_surface import documents_to_text
from helpers.agent.session_auth import (
    CapturedSession,
    build_session_nuclei_template,
)
from helpers.checks.nuclei.construct_temp import (
    construct_login_template,
    construct_navigate_action,
    construct_navigate_template,
)
from helpers.checks.nuclei.run_nuclei import run_nuclei

console = Console(markup=False)


def _write_secure_temp_yaml(content: str) -> str:
    fd, path = tempfile.mkstemp(prefix="dast_tpl_", suffix=".yaml")
    try:
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def fetch_authenticated_page(
    url: str,
    auth: AuthRequirements,
    timeout_seconds: int = 90,
    egress_proxy: str | None = None,
    session: CapturedSession | None = None,
) -> tuple[str, list[Document]]:
    if session is not None:
        new_template = build_session_nuclei_template(session, url, extract_html=True, placeholder=False)
    else:
        new_login_template = construct_login_template(auth)
        new_navigate_template = construct_navigate_template(url)
        new_template = new_login_template + new_navigate_template

    temp_path = _write_secure_temp_yaml(new_template)
    try:
        documents = run_nuclei(
            template_path=temp_path,
            url=url,
            timeout_seconds=timeout_seconds,
            egress_proxy=egress_proxy,
        )
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
    if session is not None:
        documents = session.scrub_documents(documents)
    page_content = documents_to_text(documents)
    console.print(f"HTML Page content length: {len(page_content)} characters", style="bold green")
    return page_content, documents


def get_page_content(
    url: str,
    auth: AuthRequirements,
    timeout_seconds: int = 90,
    egress_proxy: str | None = None,
    session: CapturedSession | None = None,
) -> str:
    try:
        page_content, _documents = fetch_authenticated_page(
            url, auth, timeout_seconds=timeout_seconds, egress_proxy=egress_proxy, session=session
        )
        return page_content
    except Exception as e:
        console.print(f"Error in getting page content: {e}", style="bold red")
        raise Exception(f"Error in getting page content: {e}")


def get_auth_login_template(
    url: str,
    auth: AuthRequirements,
    session: CapturedSession | None = None,
) -> str:
    try:
        if session is not None:
            # Placeholders only: real cookies/JWTs/storage are injected right before run_nuclei, never sent to the LLM.
            base = build_session_nuclei_template(session, url, extract_html=False, placeholder=True)
            return base + "\n<ADD_YOUR_EXPLOIT_ACTIONS_HERE>"
        new_login_template = construct_login_template(auth)
        new_navigate_template = construct_navigate_action(url)
        return new_login_template + new_navigate_template + "\n\n<ADD_YOUR_EXPLOIT_ACTIONS_HERE>"
    except Exception as e:
        console.print(f"Error in getting auth login template: {e}", style="bold red")
        raise Exception(f"Error in getting auth login template: {e}")
