from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.services.analysis import analyze_events
from app.services.decoder import DecodeError, decode_pcap
from app.services.storage import save_upload

app = FastAPI(title="TraceLens AI API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+):30\d{2}",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/traces")
async def upload_trace(
    file: UploadFile = File(...),
    http2_ports: str = Form("29502,29503,29504,29507,29509,29518"),
    show_heartbeats: bool = Form(False),
    hide_duplicate_pfcp: bool = Form(True),
) -> dict:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only PCAP, PCAPNG, or CAP files are supported")

    pcap_path = await save_upload(file)

    try:
        decoded = decode_pcap(pcap_path)
    except DecodeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    analysis = analyze_events(decoded.events)
    return {
        "trace_id": decoded.trace_id,
        "filename": file.filename,
        "event_count": len(decoded.events),
        "events": decoded.events[:200],
        "errors": analysis.errors,
        "ai_context": analysis.ai_context,
        "settings": {
            "http2_ports": normalize_ports(http2_ports),
            "show_heartbeats": show_heartbeats,
            "hide_duplicate_pfcp": hide_duplicate_pfcp,
        },
    }


@app.post("/analysis/ai-context")
def build_ai_context(payload: dict) -> dict:
    events = payload.get("events", [])
    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="events must be a list")

    analysis = analyze_events(events)
    return analysis.ai_context


def normalize_ports(value: str) -> list[int]:
    ports = []
    for raw_port in value.split(","):
        raw_port = raw_port.strip()
        if not raw_port:
            continue
        try:
            port = int(raw_port)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    return ports
