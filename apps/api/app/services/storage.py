import os
from pathlib import Path
from uuid import uuid4

from fastapi import UploadFile


UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "uploads"))


async def save_upload(file: UploadFile) -> Path:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    suffix = Path(file.filename or "trace.pcap").suffix
    target = UPLOAD_DIR / f"{uuid4().hex}{suffix}"

    with target.open("wb") as output:
        while chunk := await file.read(1024 * 1024):
            output.write(chunk)

    return target

