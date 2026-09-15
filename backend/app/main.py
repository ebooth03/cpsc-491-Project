from fastapi import FastAPI

from app.config.settings import settings
from app.routes.scans import router as scans_router


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)

app.include_router(scans_router)


@app.get("/")
def root():
    return {"message": "Vulnerability Scanner API"}