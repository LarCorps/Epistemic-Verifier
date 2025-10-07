
# Epistemic Verifier (CLI + Web)

A reference Python verifier for Epistemic Recorder outputs. It can:
- Extract the embedded CBOR+COSE manifest from JPEG APP11 (`ATVX`) or MP4 UUID boxes (`ATVX`/`ATVZ`).
- Recompute file-level SHA-256 and (optionally) chunk/rolling-hash if chunk offsets are present.
- Validate COSE_Sign1 signatures (PS256/ES256/EdDSA supported) against the public key/material in the manifest.
- Evaluate a **Trust Tier** (Gold/Silver/Untrusted/Failed) compatible with the mobile app.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# CLI
python -m epistemic_verifier.cli verify /path/to/file.jpg
python -m epistemic_verifier.cli verify /path/to/file.mp4 --details

# Web (drag & drop UI)
python -m epistemic_verifier.webapp
# then open http://127.0.0.1:5000
```
