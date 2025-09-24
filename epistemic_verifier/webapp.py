
import os, json
from flask import Flask, request, jsonify
from .verifier import verify_path

app = Flask(__name__)

@app.get('/')
def index():
    return INDEX_HTML

@app.post('/verify')
def verify():
    if 'file' not in request.files:
        return jsonify({'error': 'no file'}), 400
    f = request.files['file']
    tmp_path = os.path.join('/tmp', f.filename)
    f.save(tmp_path)
    res = verify_path(tmp_path, details=True)
    try:
        os.remove(tmp_path)
    except Exception:
        pass
    return jsonify({
        'outcome': res.outcome,
        'reason': res.reason,
        'tier': res.tier,
        'file_sha256': res.file_sha256,
        'chain_status': res.chain_status,
        'signature_status': res.signature_status,
        'watermark_status': res.watermark_status,
        'attestation_status': res.attestation_status,
        'details': res.details,
        'manifest': res.manifest,
    })

INDEX_HTML = """<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Epistemic Verifier</title>
<style>
  html, body { height:100%; margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  .wrap { display:flex; align-items:center; justify-content:center; height:100%; background:#0b0f14; color:#e6edf3; }
  .card { background:#111826; border:1px solid #1f2a3a; border-radius:16px; padding:24px; width:min(720px, 92vw); box-shadow: 0 8px 30px rgba(0,0,0,.35); }
  h1 { margin:0 0 12px 0; font-size:24px; }
  .drop { border:2px dashed #2b3b55; border-radius:12px; padding:28px; text-align:center; transition: background .2s, border-color .2s; }
  .drop.drag { background:#0f1a2b; border-color:#4a90e2; }
  .btn { display:inline-block; padding:10px 16px; border-radius:10px; border:1px solid #2b3b55; cursor:pointer; margin-top:12px;}
  pre { background:#0d1420; color:#b8c7e0; padding:12px; border-radius:8px; overflow:auto; max-height: 280px;}
  .status { margin-top:12px; padding:10px; border-radius:8px; font-weight:600;}
  .PASS { background:#0d2817; color:#9be69b; border:1px solid #1e7a3b;}
  .FAIL { background:#2a0f14; color:#f29e99; border:1px solid #7a1e1e;}
  .UNTRUSTED { background:#2a2410; color:#e6d37b; border:1px solid #7a6b1e;}
  .UNVERIFIED { background:#1f2430; color:#c9c9d1; border:1px solid #2b3b55;}
</style>
</head>
<body>
<div class=\"wrap\">
  <div class=\"card\">
    <h1>Epistemic Verifier</h1>
    <div id=\"drop\" class=\"drop\">
      <p><strong>Drag & drop</strong> a JPEG or MP4 here</p>
      <input id=\"file\" type=\"file\" accept=\"image/jpeg,video/mp4\" style=\"display:none\" />
      <div class=\"btn\" onclick=\"document.getElementById('file').click()\">Select file</div>
    </div>
    <div id=\"status\"></div>
    <pre id=\"out\" style=\"display:none\"></pre>
  </div>
</div>
<script>
const drop = document.getElementById('drop');
const file = document.getElementById('file');
const out = document.getElementById('out');
const status = document.getElementById('status');

function show(res){
  out.style.display = 'block';
  out.textContent = JSON.stringify(res, null, 2);
  status.className = 'status ' + (res.outcome || 'UNVERIFIED');
  status.textContent = (res.outcome || 'UNVERIFIED') + ' — ' + (res.reason || '');
}

async function send(file){
  const fd = new FormData();
  fd.append('file', file, file.name);
  const r = await fetch('/verify', { method: 'POST', body: fd });
  const j = await r.json();
  show(j);
}

['dragenter','dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('drag'); }));
['dragleave','drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('drag'); }));
drop.addEventListener('drop', e => {
  const f = e.dataTransfer.files[0];
  if (f) send(f);
});
file.addEventListener('change', e => {
  const f = file.files[0];
  if (f) send(f);
});
</script>
</body>
</html>"""

if __name__ == '__main__':
    app.run(debug=True)
