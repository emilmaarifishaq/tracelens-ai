# Windows Testing Guide — Latest Fixes

This covers everything fixed/added on the `claude/tracelens-ai-review-kgf77y` branch:
the "Checking API..." stuck-spinner fix, TLS keylog decryption, multi-provider AI
(OpenAI/Claude/Gemini/Ollama/Azure/custom — actually routing correctly now), and the
Diameter decoder fix.

## 1. Get the right code

`main` is far behind — **none** of these fixes are there yet. You need the feature branch:

```powershell
cd tracelens-ai
git fetch origin
git checkout claude/tracelens-ai-review-kgf77y
git pull origin claude/tracelens-ai-review-kgf77y
```

## 2. Check your Python version — this is the #1 blocker

```powershell
python --version
```

**Must be 3.12 or 3.13.** Python 3.14 breaks `pydantic-core`'s build (PyO3 doesn't
support it yet) — this exact error has already bitten this project once. If you're on
3.14, install 3.12 or 3.13 from python.org alongside it, and use that specific
interpreter in the next step (e.g. `py -3.13` instead of bare `python`).

## 3. If you have a previously-broken `.venv`, delete it first

`start.ps1` **skips Python setup entirely if `apps\api\.venv` already exists** — so a
venv built earlier against the wrong Python version will just keep silently being
reused. Force a clean rebuild:

```powershell
Remove-Item -Recurse -Force apps\api\.venv
Remove-Item -Recurse -Force apps\web\node_modules
Remove-Item -Recurse -Force apps\web\.next
```

## 4. Run the startup script

```powershell
powershell -ExecutionPolicy Bypass -File start.ps1
```

This opens two separate PowerShell windows (API on port 8000, web on port 3000).
**Check both windows for errors** — especially the API window, for the exact
`pydantic-core`/PyO3 error if step 2 was skipped.

## 5. Open it

**http://localhost:3000**

(Both `localhost` and `127.0.0.1` now work — a Next.js dev-server security check that
only trusted `localhost` by default was blocking `127.0.0.1` before; that's fixed.)

You should see **"API Connected ✓" / "TShark Available ✓"** in the top right within a
few seconds, not a stuck "Checking API..." spinner.

## 6. What's new to actually test

- **TLS keylog decryption**: Trace Options now has a "TLS keylog file" upload next to
  "Endpoint mapping." If you have a `SSLKEYLOGFILE`-format keylog matching a captured
  TLS session, upload both and TLS/QUIC traffic in that session decrypts automatically.
- **AI provider selection actually works now**: Settings → pick OpenAI, Claude, Gemini,
  Azure, Ollama, or a custom endpoint, enter your key, click Save, then click
  **"Explain Locally"** (next to the Question field in the TraceLens Explanation panel —
  same row, easy to miss if your window is narrow). This used to silently always use
  OpenAI's endpoint regardless of what you picked; now it genuinely routes to the
  provider you select.
- **Diameter failure detection**: a real bug where Diameter AVPs (Session-Id,
  Result-Code, etc.) were silently dropped by tshark's JSON output is fixed — Diameter
  failures like `DIAMETER_ERROR_USER_UNKNOWN` now get correctly detected and explained.

## 7. If it's still stuck on "Checking API..."

Open PowerShell and test the backend directly, bypassing the browser entirely:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/system/health
```

- **Hangs or errors** → the backend isn't actually running; check the API window for a
  crash/traceback.
- **Works instantly** → the backend's fine; check `netsh winhttp show proxy` — a
  system-wide proxy without a localhost bypass can intercept `127.0.0.1` traffic on some
  corporate/managed Windows machines.
