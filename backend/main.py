from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()


# Allow your frontend running on another local port
# to communicate with this backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# This describes the JSON we expect from the frontend.
class ScanConfig(BaseModel):
    target: str
    ports: str
    intensity: str
    scan_type: str


@app.get("/")
def home():
    return {
        "message": "Vulnerability Scanner API is running"
    }


@app.post("/api/scans")
def start_scan(scan: ScanConfig):

    print("Received scan configuration:")
    print("Target:", scan.target)
    print("Ports:", scan.ports)
    print("Intensity:", scan.intensity)
    print("Scan Type:", scan.scan_type)

    # No real scan yet.
    # Just return mock data so the frontend can confirm
    # that communication works.
    return {
        "scan_id": 1,
        "status": "accepted",
        "message": "Mock scan started successfully",
        "configuration": {
            "target": scan.target,
            "ports": scan.ports,
            "intensity": scan.intensity,
            "scan_type": scan.scan_type
        }
    }