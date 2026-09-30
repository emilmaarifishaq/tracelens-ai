import os
import shutil
from pathlib import Path

# Standard install locations, checked when `tshark` isn't on PATH. Wireshark's
# Windows installer doesn't add itself to PATH, and the macOS .app bundle keeps
# tshark inside the bundle, so a working install is often invisible to a bare
# `tshark` lookup -- which surfaced as "TShark Not Found" next to "API Connected".
_FALLBACK_LOCATIONS = [
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "tshark.exe",
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark" / "tshark.exe",
    Path("/Applications/Wireshark.app/Contents/MacOS/tshark"),
    Path("/opt/homebrew/bin/tshark"),
    Path("/usr/local/bin/tshark"),
    Path("/usr/bin/tshark"),
    Path("/usr/sbin/tshark"),
]


def find_tshark() -> str | None:
    """Return the tshark executable to run, or None if it can't be found.

    Order: the TSHARK_PATH env var (a file, or the Wireshark folder), then PATH,
    then the standard install locations above.
    """
    override = os.environ.get("TSHARK_PATH", "").strip().strip('"')
    if override:
        candidate = Path(override)
        if candidate.is_dir():
            for name in ("tshark.exe", "tshark"):
                if (candidate / name).is_file():
                    return str(candidate / name)
        elif candidate.is_file():
            return str(candidate)

    on_path = shutil.which("tshark")
    if on_path:
        return on_path

    for candidate in _FALLBACK_LOCATIONS:
        if candidate.is_file():
            return str(candidate)
    return None
