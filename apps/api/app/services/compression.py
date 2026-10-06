import os
import tarfile
import zipfile
from pathlib import Path
from typing import List

from fastapi import UploadFile


COMPRESSED_EXTENSIONS = {".zip", ".tar", ".tar.gz", ".tgz", ".7z"}
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def is_compressed_file(filename: str) -> bool:
    """Check if file is a compressed archive."""
    filename_lower = filename.lower()
    for ext in COMPRESSED_EXTENSIONS:
        if filename_lower.endswith(ext):
            return True
    return False


def _extract_single_archive(file_path: Path) -> None:
    """Extract a single archive file to its directory."""
    filename_lower = file_path.name.lower()
    extract_path = file_path.parent

    if filename_lower.endswith(".zip"):
        with zipfile.ZipFile(file_path, "r") as zf:
            zf.extractall(extract_path)
    elif filename_lower.endswith((".tar.gz", ".tgz")):
        with tarfile.open(file_path, "r:gz") as tf:
            tf.extractall(extract_path)
    elif filename_lower.endswith(".tar"):
        with tarfile.open(file_path, "r") as tf:
            tf.extractall(extract_path)
    elif filename_lower.endswith(".7z"):
        try:
            import py7zr

            with py7zr.SevenZipFile(file_path, "r") as szf:
                szf.extractall(extract_path)
        except ImportError:
            raise ImportError(
                "7z support requires py7zr. Install with: pip install py7zr"
            )
    else:
        raise ValueError(f"Unsupported compression format: {file_path.name}")


def _recursively_extract_archives(extract_dir: Path, max_depth: int = 5, current_depth: int = 0) -> None:
    """
    Recursively extract all compressed files found in directory.
    Prevents infinite loops with max_depth limit.
    """
    if current_depth >= max_depth:
        return

    extracted_any = False
    for file_path in extract_dir.rglob("*"):
        if not file_path.is_file():
            continue

        if is_compressed_file(file_path.name):
            try:
                _extract_single_archive(file_path)
                # Remove the archive after successful extraction
                file_path.unlink()
                extracted_any = True
            except Exception:
                # Skip files that can't be extracted
                pass

    # Recursively check for more archives
    if extracted_any:
        _recursively_extract_archives(extract_dir, max_depth, current_depth + 1)


async def extract_compressed_file(
    file: UploadFile, extract_dir: Path
) -> List[Path]:
    """
    Extract compressed file and return list of PCAP files found.
    Supports: zip, tar, tar.gz, 7z
    Handles nested/recursive compression (e.g., zip containing tars).
    """
    if not file.filename:
        raise ValueError("Filename is required")

    extract_dir.mkdir(parents=True, exist_ok=True)
    filename_lower = file.filename.lower()
    pcap_files = []

    try:
        # Save uploaded file temporarily
        temp_file = extract_dir / f"temp_{file.filename}"
        with temp_file.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                output.write(chunk)

        # Extract initial file
        _extract_single_archive(temp_file)
        temp_file.unlink()

        # Recursively extract any nested archives
        _recursively_extract_archives(extract_dir)

        # Find all PCAP files recursively
        for root, _, files in os.walk(extract_dir):
            for fname in files:
                if any(fname.lower().endswith(ext) for ext in PCAP_EXTENSIONS):
                    pcap_files.append(Path(root) / fname)

        if not pcap_files:
            raise ValueError(
                f"No PCAP files found in archive. Supported: {', '.join(PCAP_EXTENSIONS)}"
            )

        return pcap_files

    except (zipfile.BadZipFile, tarfile.TarError) as e:
        raise ValueError(f"Failed to extract archive: {str(e)}")


def get_file_type(filename: str) -> str:
    """Determine file type: 'compressed' or 'pcap'."""
    if is_compressed_file(filename):
        return "compressed"
    elif any(filename.lower().endswith(ext) for ext in PCAP_EXTENSIONS):
        return "pcap"
    return "unknown"
