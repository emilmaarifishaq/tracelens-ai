from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.services.ai_analysis import explain_trace_context
from app.services.analysis import analyze_events
from app.services.decoder import DecodeError, decode_pcaps
from app.services.endpoint_mapping import parse_endpoint_mapping
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


@app.get("/system/health")
def system_health() -> dict[str, str | bool]:
    import subprocess

    tshark_available = False
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            timeout=5,
            check=False
        )
        tshark_available = result.returncode == 0
    except Exception:
        tshark_available = False

    return {
        "status": "ok",
        "api": "ok",
        "tshark_available": tshark_available
    }


@app.post("/traces")
async def upload_trace(
    file: UploadFile | None = File(None),
    files: list[UploadFile] | None = File(None),
    mapping_file: UploadFile | None = File(None),
    http2_ports: str = Form("29502,29503,29504,29507,29509,29518"),
    show_heartbeats: bool = Form(False),
    hide_duplicate_pfcp: bool = Form(True),
) -> dict:
    uploads = list(files or [])
    if file is not None:
        uploads.append(file)

    if not uploads:
        raise HTTPException(status_code=400, detail="Upload at least one PCAP, PCAPNG, or CAP file")

    for upload in uploads:
        if not upload.filename:
            raise HTTPException(status_code=400, detail="Missing filename")
        if not upload.filename.endswith((".pcap", ".pcapng", ".cap")):
            raise HTTPException(status_code=400, detail="Only PCAP, PCAPNG, or CAP files are supported")

    pcap_paths = [await save_upload(upload) for upload in uploads]
    ports = normalize_ports(http2_ports)
    endpoint_mapping = await parse_endpoint_mapping(mapping_file)

    try:
        decoded = decode_pcaps(pcap_paths, http2_ports=ports)
    except DecodeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    settings = {
        "http2_ports": ports,
        "show_heartbeats": show_heartbeats,
        "hide_duplicate_pfcp": hide_duplicate_pfcp,
    }
    analysis = analyze_events(decoded.events, endpoint_mapping=endpoint_mapping, settings=settings)
    return {
        "trace_id": decoded.trace_id,
        "filename": ", ".join(upload.filename or "trace.pcap" for upload in uploads),
        "file_count": len(uploads),
        "event_count": analysis.ai_context["trace_summary"]["event_count"],
        "raw_event_count": len(decoded.events),
        "events": analysis.ai_context["events"][:300],
        "errors": analysis.errors,
        "ai_context": analysis.ai_context,
        "settings": settings,
        "endpoint_mapping_count": len(endpoint_mapping),
    }


@app.post("/analysis/ai-context")
def build_ai_context(payload: dict) -> dict:
    events = payload.get("events", [])
    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="events must be a list")

    analysis = analyze_events(events)
    return analysis.ai_context


@app.post("/analysis/explain")
def explain_trace(payload: dict) -> dict:
    ai_context = payload.get("ai_context")
    if not isinstance(ai_context, dict):
        events = payload.get("events", [])
        if not isinstance(events, list):
            raise HTTPException(status_code=400, detail="ai_context must be an object or events must be a list")
        ai_context = analyze_events(events).ai_context

    return explain_trace_context(
        ai_context=ai_context,
        question=str(payload.get("question") or ""),
        use_ai=bool(payload.get("use_ai", True)),
        mask_identifiers=bool(payload.get("mask_identifiers", True)),
        api_key=payload.get("api_key"),
        model=payload.get("model"),
        web_search_enabled=payload.get("web_search_enabled"),
        base_url=payload.get("base_url"),
    )


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
