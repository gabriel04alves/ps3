from fastapi import FastAPI
from scanner.api import router

app = FastAPI(title="Scanner SSL/TLS", version="1.0")
app.include_router(router)
