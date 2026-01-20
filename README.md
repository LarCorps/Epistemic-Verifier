
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

## Details output (AOCV optical verification)

For video assets, `--details` includes `details.aocv_verification`, a consolidated report:

```json
{
  "version": "AOCV_V1_OPTICAL",
  "status": "PASS|UNVERIFIED|FAIL",
  "reason": "...",
  "channels": {
    "focus_fine": {
      "confirmed": true,
      "correlation": 0.42,
      "p_value": 0.003,
      "event_p_value": 0.006,
      "events_confirmed": 5,
      "events_required": 3,
      "lag_frames": 2
    },
    "focus_coarse": { "events_declared": 2, "events_confirmed": 2, "confirmed": true }
  },
  "diagnostics": {
    "sample_fps": 10.0,
    "scale_width": 320,
    "scale_height": 180,
    "frame_ms": 100.0,
    "tile_rows": 4,
    "tile_cols": 4
  }
}
```

For `focus_fine`, confirmation is based on correlation significance; event-window
fields are diagnostic only. For `focus_coarse`, event-window tests remain
authoritative.

## License (Attribution)

Copyright (c) 2026 Epistemic Verifier contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following condition:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software. In addition, attribution to
"Epistemic Verifier" and a link to the project repository shall be included in
documentation or credits for any distribution or public use.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
