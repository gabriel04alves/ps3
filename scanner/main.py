import os

from fastapi import FastAPI
from api import router


def _prefix_from_env() -> str:
    prefix = os.getenv("API_PREFIX", "").strip().rstrip("/")
    if prefix and not prefix.startswith("/"):
        prefix = f"/{prefix}"
    return prefix


API_PREFIX = _prefix_from_env()

app = FastAPI(
    title="Scanner SSL/TLS",
    version="1.0",
    docs_url=f"{API_PREFIX}/docs" if API_PREFIX else "/docs",
    openapi_url=f"{API_PREFIX}/openapi.json" if API_PREFIX else "/openapi.json",
    root_path=os.getenv("FASTAPI_ROOT_PATH", "").strip().rstrip("/"),
)
app.include_router(router)

if API_PREFIX:
    app.include_router(router, prefix=API_PREFIX)
