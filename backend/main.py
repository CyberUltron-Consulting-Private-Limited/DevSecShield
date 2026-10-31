
import os
import contextlib
import logging
import re
from rich.console import Console
from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from backend.routers.auth import router as auth_router
from backend.routers.scans import router as scans_router
from backend.routers.certin import router as certin_router
from backend.routers.cbom_deliverables import router as cbom_deliverables_router
from backend.routers.cbom_sources import router as cbom_sources_router
from backend.routers.cbom_node import router as cbom_node_router
from backend.routers.cbom_vendor_public import router as cbom_vendor_public_router
from backend.routers.guardrails import router as guardrails_router
from backend.routers.cicd import router as cicd_router
from backend.routers.dast_profiles import router as dast_profiles_router
from backend.routers.guardrails_public import router as guardrails_public_router
from backend.routers.admin import router as admin_router
from backend.routers.team import router as team_router
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
import json
from starlette.responses import JSONResponse

console = Console()

# SECURITY: Log filter to redact sensitive credentials
class CredentialRedactionFilter(logging.Filter):
    """Filter to redact sensitive information from logs."""
    PATTERNS = [
        (re.compile(r'(mongodb://|amqp://|redis://|postgres://)[^\s]+', re.I), r'\1[REDACTED]'),
        (re.compile(r'(api[_-]?key.*?[:=]\s*["\']?)([a-zA-Z0-9]{16,})', re.I), r'\1[REDACTED]'),
        (re.compile(r'(Bearer\s+)([a-zA-Z0-9._-]+)', re.I), r'\1[REDACTED]'),
        (re.compile(r'(password.*?[:=]\s*["\']?)([^\s"\']+)', re.I), r'\1[REDACTED]'),
        (re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'), '[JWT_REDACTED]'),
        (re.compile(r'(secret.*?[:=]\s*["\']?)([^\s"\']{8,})', re.I), r'\1[REDACTED]'),
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            for pattern, replacement in self.PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        if hasattr(record, 'args') and record.args:
            try:
                record.args = tuple(
                    self._redact(arg) if isinstance(arg, str) else arg
                    for arg in record.args
                )
            except (TypeError, AttributeError):
                pass
        return True
    
    def _redact(self, text: str) -> str:
        for pattern, replacement in self.PATTERNS:
            text = pattern.sub(replacement, text)
        return text

# Apply filter to root logger
logging.getLogger().addFilter(CredentialRedactionFilter())
console.print("[bold green]✓ Credential redaction filter applied to logging[/bold green]")

# SECURITY: Load CORS origins from environment variable
def get_cors_origins() -> list[str]:
    """Get allowed CORS origins from environment variable."""
    origins_str = os.getenv("CORS_ORIGINS", "")
    if not origins_str:
        # Default to localhost for development plus production frontend
        console.print("[bold yellow]⚠ CORS_ORIGINS not set, defaulting to localhost + production[/bold yellow]")
        return [
            "http://localhost:3000",
            "http://localhost:4000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:4000",
            "https://devsecshield.zeroshield.ai",
        ]
    return [origin.strip() for origin in origins_str.split(",") if origin.strip()]

CORS_ALLOWED_ORIGINS = get_cors_origins()
console.print(f"[bold green]✓ CORS allowed origins: {CORS_ALLOWED_ORIGINS}[/bold green]")

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to tune threadpool concurrency on startup."""
    # Startup: increase threadpool token limit for bcrypt and other sync I/O under load
    try:
        import anyio.to_thread
        limiter = anyio.to_thread.current_default_thread_limiter()
        limiter.total_tokens = 100  # Increase from default ~40 to allow more concurrent sync ops
        console.print(f"[bold green]✓ Threadpool tokens increased to {limiter.total_tokens}[/bold green]")
    except Exception as e:
        console.print(f"[bold yellow]⚠ Could not tune threadpool: {e}[/bold yellow]")
    
    yield
    
    # Shutdown: no cleanup needed
    console.print("[bold yellow]Shutting down...[/bold yellow]")


app = FastAPI(lifespan=lifespan, middleware=[
    Middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
])

# setting the environment variable to False for local development
# os.environ["IS_DOCKER_CONTAINER"] = "True"  # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️


BASE_MEDIA_PATH = "uploads\\"

app.include_router(cicd_router)
app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(dast_profiles_router)
app.include_router(certin_router)
app.include_router(cbom_deliverables_router)
# CBOM Sources: team UI routes, the scan-node API and public vendor questionnaire links.
app.include_router(cbom_sources_router)
app.include_router(cbom_node_router)
app.include_router(cbom_vendor_public_router)
# DEPRECATED: Guardrails routers remain for legacy/API callers; product UI no longer exposes Guardrails.
app.include_router(guardrails_router)
app.include_router(guardrails_public_router)
app.include_router(admin_router)
app.include_router(team_router)

# Health check endpoint for container orchestration
@app.get("/health", tags=["health"])
async def health_check():
    """
    Health check endpoint for Docker health checks and load balancer probes.
    Returns 200 OK if the service is healthy.
    """
    return {"status": "healthy", "service": "devsecshield-backend"}

# Use this only for debugging purposes ⚠️⚠️⚠️⚠️
# @app.exception_handler(RequestValidationError)
# @app.exception_handler(ValidationError)
# async def validation_exception_handler(request, exc):
#     # write error to a txt file 
#     with open("validation_error.txt", "w+") as f:
#         f.write(str(exc))
#     return JSONResponse({"message": "Validation error", "data": None}, status_code=422)

if __name__=="__main__":

    Console().print("Ran main.py ✔️",style="bold green")
