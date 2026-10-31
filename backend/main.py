import os
import re

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.routes import router

app = FastAPI(
    title="ChainSight AI",
    version="0.1.0",
    description="Offline, evidence-backed EDR investigation prototype",
)

configured_origins = [
    origin.strip()
    for origin in os.getenv("CHAINSIGHT_CORS_ORIGINS", "").split(",")
    if origin.strip()
]

default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:5175",
    "http://127.0.0.1:5175",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8100",
    "http://127.0.0.1:8100",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

cors_origins = list(dict.fromkeys(configured_origins + default_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)
