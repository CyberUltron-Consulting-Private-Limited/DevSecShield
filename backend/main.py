
import os
import contextlib
from rich.console import Console
from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from backend.routers.auth import router as auth_router
from backend.routers.scans import router as scans_router
from backend.routers.guardrails import router as guardrails_router
from backend.routers.cicd import router as cicd_router
from backend.routers.guardrails_public import router as guardrails_public_router
from backend.routers.admin import router as admin_router
from backend.routers.team import router as team_router
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
import json
from starlette.responses import JSONResponse

console = Console()

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
        allow_origins=["*"],  # consider restricting to ["http://localhost:3000"] in dev
        allow_credentials=True,
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
app.include_router(guardrails_router)
app.include_router(guardrails_public_router)
app.include_router(admin_router)
app.include_router(team_router)

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
