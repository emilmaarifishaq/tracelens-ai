import argparse
import shutil
import urllib.request
import zipfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "samples" / "external-captures.yaml"
CACHE_DIR = ROOT / "samples" / "external" / "_archives"


def main() -> None:
    parser = argparse.ArgumentParser(description="Download approved external TraceLens sample captures.")
    parser.add_argument("--technology", choices=["4G", "5G", "supporting"], help="Only download one capture group.")
    parser.add_argument("--id", help="Only download one capture id.")
    args = parser.parse_args()

    manifest = yaml.safe_load(MANIFEST.read_text())
    captures = list(manifest.get("captures", [])) + list(manifest.get("supporting_captures", []))

    selected = [capture for capture in captures if include_capture(capture, args.technology, args.id)]
    if not selected:
        raise SystemExit("No captures matched the requested filters.")

    for capture in selected:
        if capture.get("archive_url"):
            download_from_archive(capture)
        else:
            download_file(capture["download_url"], ROOT / capture["local_path"])
        print(f"{capture['id']}: {capture['local_path']}")


def include_capture(capture: dict, technology: str | None, capture_id: str | None) -> bool:
    if capture_id and capture.get("id") != capture_id:
        return False
    if not technology:
        return True
    if technology == "supporting":
        return capture.get("technology") in {"4G/5G transport", "IMS/VoLTE support"}
    return capture.get("technology") == technology


def download_from_archive(capture: dict) -> None:
    archive_url = capture["archive_url"]
    archive_path = CACHE_DIR / Path(archive_url).name
    download_file(archive_url, archive_path)

    member = capture["archive_member"]
    target_path = ROOT / capture["local_path"]
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        with archive.open(member) as source, target_path.open("wb") as target:
            shutil.copyfileobj(source, target)


def download_file(url: str, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists() and target_path.stat().st_size > 0:
        return
    with urllib.request.urlopen(url, timeout=60) as response, target_path.open("wb") as target:
        shutil.copyfileobj(response, target)


if __name__ == "__main__":
    main()
