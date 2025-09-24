
from typing import Optional, Dict, Any
from .result import VerifyOutcome, VerifyResult
from .hashing import sha256_file, verify_chunk_chain
from .jpeg_parser import find_app11_atvx
from .mp4_parser import find_uuid_atvx
from .cbor_cose import parse_cose_sign1, verify_cose_sign1
from .attestation import evaluate_tier
from .watermark import check_watermark_stub
import cbor2

def _extract_manifest_blob(path: str) -> Dict[str, Any]:
    raw = None
    if path.lower().endswith(('.jpg', '.jpeg')):
        raw = find_app11_atvx(path)
    else:
        raw = find_uuid_atvx(path)
    if not raw:
        raise ValueError("No embedded ATVX/ATVZ manifest found")
    try:
        cose = parse_cose_sign1(raw)
        return {'format': 'cose_sign1', 'cose': cose, 'payload': cose['payload']}
    except Exception:
        return {'format': 'cbor', 'cbor': raw, 'payload': raw}

def verify_path(path: str, *, details: bool = False, public_key_pem: Optional[bytes] = None) -> VerifyResult:
    file_hash = sha256_file(path)
    man = _extract_manifest_blob(path)
    manifest = None
    sig_status = "UNVERIFIED"
    if man['format'] == 'cose_sign1':
        cose = man['cose']
        manifest = cbor2.loads(cose['payload'])
        if public_key_pem:
            sig_ok = verify_cose_sign1(cose, public_key_pem)
            sig_status = "PASS" if sig_ok else "FAIL"
    else:
        manifest = cbor2.loads(man['payload'])
    pin_ok = True
    pin_expected = None
    if isinstance(manifest, dict):
        pin_expected = (manifest.get('media') or {}).get('sha256')
        if pin_expected:
            pin_ok = str(pin_expected).lower() == file_hash.lower()
    chain_status = "UNVERIFIED"
    chain_ok = True
    diag = None
    chunks = (manifest.get('chunks') if isinstance(manifest, dict) else None) or []
    if chunks:
        try:
            with open(path, 'rb') as f:
                chain_ok, diag = verify_chunk_chain(f, chunks)
                chain_status = "PASS" if chain_ok else "FAIL"
        except Exception as e:
            chain_status = "UNVERIFIED"
            diag = {'error': str(e)}
    wm_status = check_watermark_stub(path)
    tier, tier_reason = evaluate_tier(manifest if isinstance(manifest, dict) else {})
    if sig_status == "FAIL" or (pin_expected and not pin_ok) or chain_status == "FAIL":
        outcome = VerifyOutcome.FAIL
        reason = "Signature/pin/chain failed"
    elif tier in ("GOLD", "SILVER"):
        outcome = VerifyOutcome.PASS if pin_ok and (chain_status in ("PASS", "UNVERIFIED")) else VerifyOutcome.UNVERIFIED
        reason = f"Verified structure; tier {tier} ({tier_reason})"
    elif tier == "UNTRUSTED":
        outcome = VerifyOutcome.UNTRUSTED
        reason = "Structure ok but attestation untrusted"
    else:
        outcome = VerifyOutcome.UNVERIFIED
        reason = "Insufficient evidence to verify"
    return VerifyResult(
        outcome=outcome,
        reason=reason,
        tier=tier,
        file_sha256=file_hash,
        chain_status=chain_status,
        signature_status=sig_status,
        watermark_status=wm_status,
        attestation_status="PASS" if tier in ("GOLD", "SILVER") else ("UNVERIFIED" if tier == "UNTRUSTED" else "FAIL"),
        manifest=manifest if details else None,
        details={} if not details else {'pin_expected': pin_expected, 'pin_ok': pin_ok, 'chunk_diagnostics': diag, 'tier_reason': tier_reason}
    )
