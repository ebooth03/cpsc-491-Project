from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.routes.scans import router as scans_router


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(scans_router)


@app.get("/")
def root():
    return {"message": "Vulnerability Scanner API"}