from typing import Optional, Dict, Any, Tuple, List, Set
import struct
import io
import os
import json
import csv
import random
from pathlib import Path
import hashlib
import binascii
import subprocess
import math
import random
from fractions import Fraction
import cbor2
import numpy as np

from .result import VerifyOutcome, VerifyResult
from .hashing import sha256_file
from .jpeg_parser import find_app11_atvx, hash_jpeg_scan, extract_jpeg_scan, has_atix_ciphertext, extract_atix_crypto
from .mp4_parser import find_uuid_atvx
from .cbor_cose import parse_cose_sign1, verify_cose_sign1
# Watermark deprecated: do not import or check

# ---------------- MP4 parsing helpers ----------------

def _u32(b: bytes, off: int) -> int:
    return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF)

def _fourcc(s: str) -> int:
    return (ord(s[0]) << 24) | (ord(s[1]) << 16) | (ord(s[2]) << 8) | ord(s[3])

def _read_top_level_range(ch, end: int, target: int) -> Optional[Tuple[int, int]]:
    pos = 0
    hdr = bytearray(8)
    while pos + 8 <= end:
        ch.seek(pos); ch.readinto(hdr)
        size32 = struct.unpack(">I", hdr[0:4])[0]
        typ = struct.unpack(">I", hdr[4:8])[0]
        if size32 == 1:
            ext = ch.read(8); size = struct.unpack(">Q", ext)[0]; header = 16
        elif size32 == 0:
            size = end - pos; header = 8
        else:
            size = size32; header = 8
        if size <= header or pos + size > end:
            break
        if typ == target:
            return pos, size
        pos += size
    return None

def _read_range(ch, off: int, size: int) -> bytes:
    ch.seek(off)
    return ch.read(size)

def _find_child(buf: bytes, parent_start: int, parent_end: int, fourcc: str) -> Optional[Tuple[int, int]]:
    target = _fourcc(fourcc)
    cur = parent_start + 8
    while cur + 8 <= parent_end:
        box_len = _u32(buf, cur)
        box_typ = _u32(buf, cur + 4)
        if box_len <= 0 or cur + box_len > parent_end:
            break
        if box_typ == target:
            return cur, box_len
        cur += box_len
    return None

def _trak_is_video(buf: bytes, start: int, end: int) -> bool:
    mdia = _find_child(buf, start, end, "mdia")
    if not mdia: return False
    hdlr = _find_child(buf, mdia[0], mdia[0] + mdia[1], "hdlr")
    if not hdlr: return False
    try:
        return _u32(buf, hdlr[0] + 16) == _fourcc("vide")
    except Exception:
        return False

def _find_video_stbl(moov: bytes) -> Optional[bytes]:
    cur = 8
    end = len(moov)
    while cur + 8 <= end:
        l = _u32(moov, cur); t = _u32(moov, cur + 4)
        if l <= 0 or cur + l > end:
            break
        if t == _fourcc("trak") and _trak_is_video(moov, cur, cur + l):
            mdia = _find_child(moov, cur, cur + l, "mdia")
            if not mdia: return None
            minf = _find_child(moov, mdia[0], mdia[0] + mdia[1], "minf")
            if not minf: return None
            stbl = _find_child(moov, minf[0], minf[0] + minf[1], "stbl")
            if not stbl: return None
            s, ln = stbl
            return moov[s:s + ln]
        cur += l
    return None

def _parse_stsz(stbl: bytes) -> Optional[List[int]]:
    node = _find_child(stbl, 0, len(stbl), "stsz")
    if not node: return None
    p = node[0] + 8
    p += 4  # version+flags
    sample_size = _u32(stbl, p); p += 4
    count = _u32(stbl, p); p += 4
    if sample_size != 0:
        return [sample_size] * count
    out = []
    for _ in range(count):
        out.append(_u32(stbl, p)); p += 4
    return out

def _parse_stsc(stbl: bytes) -> Optional[List[Tuple[int, int]]]:
    node = _find_child(stbl, 0, len(stbl), "stsc")
    if not node: return None
    p = node[0] + 8
    p += 4
    count = _u32(stbl, p); p += 4
    out = []
    for _ in range(count):
        first_chunk = _u32(stbl, p); p += 4
        samples_per_chunk = _u32(stbl, p); p += 4
        p += 4  # sample_description_index
        out.append((first_chunk, samples_per_chunk))
    return out

def _parse_stco_or_co64(stbl: bytes) -> Optional[List[int]]:
    co64 = _find_child(stbl, 0, len(stbl), "co64")
    if co64:
        p = co64[0] + 8
        p += 4
        count = _u32(stbl, p); p += 4
        out = []
        for _ in range(count):
            out.append(int.from_bytes(stbl[p:p + 8], "big")); p += 8
        return out
    stco = _find_child(stbl, 0, len(stbl), "stco")
    if not stco: return None
    p = stco[0] + 8
    p += 4
    count = _u32(stbl, p); p += 4
    out = []
    for _ in range(count):
        out.append(_u32(stbl, p)); p += 4
    return out

def _parse_stss(stbl: bytes) -> Set[int]:
    node = _find_child(stbl, 0, len(stbl), "stss")
    if not node: return set()
    p = node[0] + 8
    p += 4
    count = _u32(stbl, p); p += 4
    out = set()
    for _ in range(count):
        out.add(_u32(stbl, p)); p += 4  # 1-based indices
    return out

def _build_sample_offsets(sample_sizes: List[int], chunk_offsets: List[int], stsc: List[Tuple[int, int]]) -> List[int]:
    out = [0] * len(sample_sizes)

    def samples_per_chunk_for(chunk_index1: int) -> int:
        cur = stsc[0]
        for e in stsc:
            if e[0] <= chunk_index1: cur = e
            else: break
        return cur[1]

    sample_index = 0
    chunk = 1
    while chunk <= len(chunk_offsets) and sample_index < len(sample_sizes):
        base = chunk_offsets[chunk - 1]
        spc = samples_per_chunk_for(chunk)
        off = base
        n = 0
        while n < spc and sample_index < len(sample_sizes):
            out[sample_index] = off
            off += sample_sizes[sample_index]
            sample_index += 1
            n += 1
        chunk += 1
    return out

def _merkle_root_hex(leaves_hex: List[str]) -> str:
    if not leaves_hex:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(h) for h in leaves_hex]
    h = hashlib.sha256
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            m = h(); m.update(left); m.update(right)
            nxt.append(m.digest())
        level = nxt
    return level[0].hex()

# ---------------- Chunk recompute (path-based; Windows-safe) ----------------

def recompute_chunk_hashes_frames_path(path: str, frames_per_chunk: int) -> List[str]:
    """
    Frame-aligned hashing over the *video* track.
    - Hash each video sample (frame) individually and feed in order.
    - Never cross a keyframe inside a chunk: if a keyframe appears within the window,
      end this chunk before it so the next chunk starts at that keyframe.
    """
    out: List[str] = []
    buf = bytearray(1024 * 1024)

    with open(path, "rb", buffering=0) as f:
        end = f.seek(0, os.SEEK_END); f.seek(0)

        moov = _read_top_level_range(f, end, _fourcc("moov"))
        if not moov: raise ValueError("moov not found")
        moov_bytes = _read_range(f, moov[0], moov[1])

        stbl = _find_video_stbl(moov_bytes)
        if not stbl: raise ValueError("video stbl not found")

        sample_sizes  = _parse_stsz(stbl) or []
        chunk_offsets = _parse_stco_or_co64(stbl) or []
        stsc          = _parse_stsc(stbl) or []
        sync_set      = _parse_stss(stbl)  # 1-based

        if not sample_sizes or not chunk_offsets or not stsc:
            raise ValueError("missing stsz/stco|co64/stsc")

        sample_offsets = _build_sample_offsets(sample_sizes, chunk_offsets, stsc)
        total = len(sample_sizes)
        if len(sample_offsets) != total: raise ValueError("tables mismatch")

        i = 0
        while i < total:
            remaining = total - i
            ln = frames_per_chunk if frames_per_chunk < remaining else remaining

            # If a keyframe is inside (not at i), end chunk just before it.
            for j in range(1, ln):
                if (i + j + 1) in sync_set:  # stss is 1-based
                    ln = j
                    break
            if ln <= 0: ln = 1  # safety

            h = hashlib.sha256()
            # hash samples [i .. i+ln)
            for k in range(ln):
                off = sample_offsets[i + k]
                sz  = sample_sizes[i + k]
                left = sz
                pos = off
                while left > 0:
                    to_read = min(len(buf), left)
                    f.seek(pos)
                    n = f.readinto(memoryview(buf)[:to_read])
                    if not n: raise IOError("unexpected EOF while reading sample")
                    h.update(buf[:n])
                    pos  += n
                    left -= n
            out.append(h.hexdigest())
            i += ln

    return out

def recompute_chunk_hashes_bytes_path(path: str, chunk_size: int) -> List[str]:
    """
    Fixed-size chunk hashing over mdat payload bytes.
    """
    out: List[str] = []
    buf = bytearray(max(1024 * 1024, chunk_size))
    carry = b""

    def emit(b: bytes):
        h = hashlib.sha256(); h.update(b); out.append(h.hexdigest())

    with open(path, "rb", buffering=0) as f:
        end = f.seek(0, os.SEEK_END); f.seek(0)
        # collect all mdat payload ranges
        segs: List[Tuple[int, int]] = []
        pos = 0
        hdr = bytearray(8)
        while pos + 8 <= end:
            f.seek(pos); f.readinto(hdr)
            size32 = struct.unpack(">I", hdr[0:4])[0]
            typ    = struct.unpack(">I", hdr[4:8])[0]
            if size32 == 1:
                ext = f.read(8); size = struct.unpack(">Q", ext)[0]; head = 16
            elif size32 == 0:
                size = end - pos; head = 8
            else:
                size = size32; head = 8
            if size <= head or pos + size > end: break
            if typ == _fourcc("mdat") and size > head:
                segs.append((pos + head, size - head))
            pos += size

        for (start, length) in segs:
            remaining = length
            pos = start

            # top up with any carry to reach a full block
            if carry:
                need = chunk_size - len(carry)
                to_read = min(need, remaining)
                f.seek(pos)
                n = f.readinto(memoryview(buf)[:to_read])
                if n:
                    carry += bytes(buf[:n])
                    pos += n; remaining -= n
                if len(carry) == chunk_size:
                    emit(carry); carry = b""

            while remaining > 0:
                to_read = min(chunk_size, remaining)
                f.seek(pos)
                n = f.readinto(memoryview(buf)[:to_read])
                if not n:
                    break
                if n == chunk_size:
                    emit(bytes(buf[:n]))
                else:
                    carry += bytes(buf[:n])
                pos += n; remaining -= n

        if not segs:
            emit(b"")
        elif carry:
            emit(carry)

    return out

# ---------------- COSE / Attestation helpers ----------------

def _decode_protected_map(m: Any) -> Dict[str, Any]:
    if isinstance(m, (bytes, bytearray)):
        try:
            return cbor2.loads(m)
        except Exception:
            return {}
    return m if isinstance(m, dict) else {}

def _cose_headers(cose: Dict[str, Any]) -> Tuple[Optional[int], Optional[bytes], Dict[str, Any]]:
    """
    Returns (alg, kid_bytes, protected_map).
    ES256 is alg = -7. 'kid' may be bytes or hex/utf-8 string.
    """
    prot = _decode_protected_map(cose.get("protected") or {})
    # COSE label 1 == alg; 4 == kid
    alg = prot.get(1, prot.get("alg"))
    kid = prot.get(4, prot.get("kid"))
    if isinstance(kid, str):
        try:
            kid = binascii.unhexlify(kid.strip())
        except Exception:
            kid = kid.encode("utf-8")
    return (int(alg) if isinstance(alg, int) else None,
            bytes(kid) if isinstance(kid, (bytes, bytearray)) else None,
            prot)

def _ensure_es256(alg: Optional[int]) -> Tuple[bool, str]:
    """
    Enforce ES256 (COSE alg = -7).
    Non-ES256 is marked UNVERIFIED (policy parity with Android).
    """
    if alg == -7:
        return True, "ES256"
    return False, f"Unsupported COSE alg={alg}; expect ES256 (-7)"

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except Exception:  # pragma: no cover
    x509 = None

def _extract_manifest_blob(path: str) -> Dict[str, Any]:
    """
    Returns {"format":"cose_sign1","cose":{...},"payload":bytes} or {"format":"cbor","payload":bytes}
    by reading JPEG APP11(ATVXJPG) or MP4 uuid(ATVX/ATVZ).
    """
    raw = find_app11_atvx(path) if path.lower().endswith(('.jpg', '.jpeg')) else find_uuid_atvx(path)
    if not raw:
        raise ValueError("No embedded ATVX/ATVZ manifest found")

    # Try COSE first; fall back to plain CBOR
    try:
        cose = parse_cose_sign1(raw)  # {'protected':..., 'payload':..., 'signature':...}
        return {"format": "cose_sign1", "cose": cose, "payload": cose["payload"]}
    except Exception:
        return {"format": "cbor", "payload": raw}

def _bytes_from_maybe_hex(b: Any) -> Optional[bytes]:
    if b is None: return None
    if isinstance(b, (bytes, bytearray)): return bytes(b)
    if isinstance(b, str):
        s = b.strip()
        try:
            return binascii.unhexlify(s)
        except Exception:
            try:
                import base64
                return base64.b64decode(s)
            except Exception:
                return None
    return None

def _leaf_pubkey_pem_from_chain(chain_items: Any) -> Optional[bytes]:
    """
    Accept list of DER blobs (or hex/base64 strings) and return leaf SPKI (PEM if cryptography available; else DER).
    """
    if not isinstance(chain_items, (list, tuple)) or not chain_items:
        return None
    leaf_der = _bytes_from_maybe_hex(chain_items[0])
    if not leaf_der:
        return None
    if x509 is None:
        return leaf_der
    try:
        cert = x509.load_der_x509_certificate(leaf_der)
        pub = cert.public_key()
        return pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        return None

def _spki_der_from_pem_or_der(pub_bytes: bytes) -> Optional[bytes]:
    """
    Convert SPKI in PEM or DER to DER bytes for SHA-256 digest.
    """
    if not pub_bytes:
        return None
    if pub_bytes.startswith(b"-----BEGIN"):
        # strip PEM armor
        try:
            body = b"".join(
                ln for ln in pub_bytes.splitlines() if b"-----" not in ln and ln.strip()
            )
            import base64
            return base64.b64decode(body)
        except Exception:
            return None
    return pub_bytes

def _verify_cose_with_attestation(cose: Dict[str, Any], manifest_map: Dict[str, Any]) -> Tuple[str, str]:
    """
    Verify COSE using an attested leaf key (video: attestation_chain/attestation.chain,
    photo: trust.cert_chain_der). Enforces ES256 and key-identity binding:
    - signer_key_id == SHA-256(SPKI)  [REQUIRED for video; OPTIONAL for photo MVP]
    - if present, COSE kid is a prefix of SHA-256(SPKI)
    Returns (signature_status, reason).
    """
    # Enforce ES256
    alg, kid, _prot = _cose_headers(cose)
    ok_alg, alg_reason = _ensure_es256(alg)
    if not ok_alg:
        return ("UNVERIFIED", alg_reason)

    # Does this manifest describe a photo?
    is_photo = (isinstance(manifest_map, dict)
                and isinstance(manifest_map.get("schema"), dict)
                and (manifest_map["schema"].get("name") == "capture.photo"))

    # Video-style: top-level attestation_chain / attestation.chain
    att_chain = (manifest_map.get("attestation_chain")
                 or (manifest_map.get("attestation") or {}).get("chain"))

    # Photo-style: trust.cert_chain_der (array of DER bytes/hex)
    trust_chain = (manifest_map.get("trust") or {}).get("cert_chain_der")

    for chain in (att_chain, trust_chain):
        if isinstance(chain, (list, tuple)) and chain:
            pem_or_der = _leaf_pubkey_pem_from_chain(chain)
            if pem_or_der:
                try:
                    ok = verify_cose_sign1(cose, pem_or_der)
                    if not ok:
                        return ("FAIL", "COSE signature invalid for attested leaf key")

                    # Key identity binding checks
                    spki_der = _spki_der_from_pem_or_der(pem_or_der)
                    if not spki_der:
                        return ("UNVERIFIED", "Could not decode SPKI from attestation leaf")
                    spki_sha256 = hashlib.sha256(spki_der).digest()

                    signer_key_id = manifest_map.get("signer_key_id")
                    # For photos, signer_key_id is OPTIONAL for MVP; for videos it's REQUIRED.
                    if signer_key_id is None and not is_photo:
                        return ("UNVERIFIED", "Manifest missing signer_key_id")
                    if isinstance(signer_key_id, str):
                        try:
                            signer_key_id = binascii.unhexlify(signer_key_id.strip())
                        except Exception:
                            signer_key_id = signer_key_id.encode("utf-8")
                    if signer_key_id is not None:
                        if not isinstance(signer_key_id, (bytes, bytearray)):
                            return ("UNVERIFIED", "Malformed signer_key_id")
                        if bytes(signer_key_id) != spki_sha256:
                            return ("FAIL", "signer_key_id != SHA-256(SPKI of attested leaf)")

                    if kid is not None:
                        if len(kid) > len(spki_sha256) or kid != spki_sha256[: len(kid)]:
                            return ("FAIL", "COSE kid is not a prefix of SHA-256(SPKI)")

                    return ("PASS", "COSE verified with attested leaf; key binding OK" if signer_key_id is not None else
                                   "COSE verified with attested leaf; (photo: signer_key_id optional)")
                except Exception as e:
                    return ("FAIL", f"COSE/attestation check failed: {e}")

    return ("UNVERIFIED", "No usable attestation leaf; COSE not verified")

# ---------------- Main entry ----------------

def _validate_aocv(payload_map: Dict[str, Any], *, expected_mode: Optional[str] = None) -> Tuple[str, str, Dict[str, Any]]:
    aocv = payload_map.get("aocv")
    if aocv is None:
        return ("UNVERIFIED", "aocv missing", {})
    if not isinstance(aocv, dict):
        return ("FAIL", "aocv not a map", {"aocv_type": str(type(aocv))})

    # Shape checks + commitment verification (canonical CBOR schedule hash).
    v = aocv.get("v")
    if not isinstance(v, int):
        return ("FAIL", "aocv.v not int", {"v": v})

    typ = aocv.get("type")
    if typ is not None and not isinstance(typ, str):
        return ("FAIL", "aocv.type not str", {"type": typ})

    mode = aocv.get("mode")
    if not isinstance(mode, str):
        return ("FAIL", "aocv.mode not str", {"mode": mode})
    if expected_mode and mode != expected_mode:
        return ("FAIL", "aocv.mode mismatch", {"mode": mode, "expected_mode": expected_mode})

    events = aocv.get("events")
    if not isinstance(events, list) or not events:
        return ("FAIL", "aocv.events missing/empty", {"events_type": str(type(events))})

    bad = 0
    min_t = None
    max_t = None
    roles = set()
    focus_codes = set()
    last_t = -1
    for e in events:
        if not isinstance(e, dict):
            bad += 1
            continue
        role = e.get("role")
        t_ms = e.get("t_ms")
        fc = e.get("focus_code")
        if not isinstance(role, str) or not isinstance(t_ms, int) or t_ms < 0 or not isinstance(fc, int):
            bad += 1
            continue
        if t_ms < last_t:
            bad += 1
            continue
        last_t = t_ms
        roles.add(role)
        focus_codes.add(fc)
        min_t = t_ms if min_t is None else min(min_t, t_ms)
        max_t = t_ms if max_t is None else max(max_t, t_ms)

    if bad:
        return ("FAIL", f"aocv.events malformed ({bad} bad)", {"events": len(events), "bad_events": bad})

    seed_commitment = aocv.get("seed_commitment")
    schedule_commitment = aocv.get("schedule_commitment")
    if seed_commitment is None or schedule_commitment is None:
        return ("FAIL", "aocv commitments missing", {"has_seed_commitment": seed_commitment is not None, "has_schedule_commitment": schedule_commitment is not None})

    if not isinstance(seed_commitment, (bytes, bytearray)) or not isinstance(schedule_commitment, (bytes, bytearray)):
        return ("FAIL", "aocv commitments not bytes", {"seed_type": str(type(seed_commitment)), "schedule_type": str(type(schedule_commitment))})

    focus_codes_map = aocv.get("focus_codes")
    if not isinstance(focus_codes_map, dict):
        return ("FAIL", "aocv.focus_codes missing/invalid", {"focus_codes_type": str(type(focus_codes_map))})
    focus_code_count = focus_codes_map.get("count")
    if not isinstance(focus_code_count, int) or focus_code_count < 2:
        return ("FAIL", "aocv.focus_codes.count invalid", {"count": focus_code_count})

    for fc in focus_codes:
        if not (0 <= fc < focus_code_count):
            return ("FAIL", "aocv focus_code out of range", {"focus_code": fc, "count": focus_code_count})

    if len(seed_commitment) != 32 or len(schedule_commitment) != 32:
        return ("FAIL", "aocv commitment length invalid", {"seed_commitment_len": len(seed_commitment), "schedule_commitment_len": len(schedule_commitment)})

    # Mode-specific requirements
    if mode == "video-micropull":
        if roles != {"VIDEO"}:
            return ("FAIL", "aocv video roles invalid", {"roles": sorted(list(roles))})
    elif mode == "photo-burst":
        if not {"MAIN", "CH1", "CH2"}.issubset(roles):
            return ("FAIL", "aocv photo roles missing", {"roles": sorted(list(roles))})
        assets = aocv.get("challenge_assets")
        if not isinstance(assets, list) or not assets:
            return ("FAIL", "aocv.challenge_assets missing/empty", {"assets_type": str(type(assets))})
        asset_roles = set()
        bad_assets = 0
        for a in assets:
            if not isinstance(a, dict):
                bad_assets += 1
                continue
            r = a.get("role")
            h = a.get("full_hash")
            if not isinstance(r, str) or not isinstance(h, (bytes, bytearray)) or len(h) != 32:
                bad_assets += 1
                continue
            asset_roles.add(r)
        if bad_assets:
            return ("FAIL", "aocv.challenge_assets malformed", {"assets": len(assets), "bad_assets": bad_assets})
        if not {"CH1", "CH2"}.issubset(asset_roles):
            return ("FAIL", "aocv.challenge_assets roles missing", {"asset_roles": sorted(list(asset_roles))})
    else:
        return ("FAIL", "aocv.mode unknown", {"mode": mode})

    # Recompute schedule commitment using canonical CBOR (should match Kotlin's canonical encoding).
    try:
        schedule_obj = {
            "v": v,
            "type": typ,
            "mode": mode,
            **({"rate_hz_milli": aocv.get("rate_hz_milli")} if aocv.get("rate_hz_milli") is not None else {}),
            "focus_code_count": focus_code_count,
            "events": [{"t_ms": e["t_ms"], "role": e["role"], "focus_code": e["focus_code"]} for e in events],
        }
        schedule_bytes = cbor2.dumps(schedule_obj, canonical=True)
        recomputed = hashlib.sha256(schedule_bytes).digest()
        if bytes(schedule_commitment) != recomputed:
            return ("FAIL", "aocv.schedule_commitment mismatch", {"recomputed_len": len(recomputed)})
    except Exception as e:
        return ("FAIL", f"aocv schedule_commitment verify error: {e}", {})

    diag = {
        "v": v,
        "type": typ,
        "mode": mode,
        "events": len(events),
        "roles": sorted(list(roles)),
        "unique_focus_codes": len(focus_codes),
        "min_t_ms": min_t,
        "max_t_ms": max_t,
        "seed_commitment_len": len(seed_commitment),
        "schedule_commitment_len": len(schedule_commitment),
        "focus_code_count": focus_code_count,
        "rate_hz_milli": aocv.get("rate_hz_milli"),
    }
    return ("PASS", "aocv present + verified", diag)


# ---------------- Optical verification (CLI-only) ----------------

_AOCV_OPTICAL_VERSION = "AOCV_V1_OBSERVATION"
_AOCV_SAMPLE_FPS = 10.0
_AOCV_SCALE_WIDTH = 640
_AOCV_TILE_ROWS = 4
_AOCV_TILE_COLS = 4
_AOCV_TILE_SAT_THRESHOLD = 0.05
_AOCV_MAX_LAG_FRAMES = 10
_AOCV_P_SHUFFLES = 1000
_AOCV_EVENT_SHUFFLES = 1000
_AOCV_EVENT_DUR_MIN_FRAMES = 10
_AOCV_EVENT_DUR_MAX_FRAMES = 14
_AOCV_SIGNAL_EPS = 1e-6
_AOCV_SHARPNESS_METRIC = "tenengrad"
_AOCV_TILE_AGGREGATE = "pca1"
_AOCV_DETREND_MIN = 11
_AOCV_DETREND_MAX = 101
_AOCV_DETREND_PERIODS = 2.5
_AOCV_ANALOG_MAX_LAG_FRAMES = 4
_AOCV_ANALOG_P_SHUFFLES = 1000
_AOCV_ANALOG_MEAN_MIN = 12.0
_AOCV_ANALOG_MEAN_MAX = 243.0
_AOCV_EVENT_MIN_SEPARATION_S = 2.0
_AOCV_EVENT_Z_THRESHOLD = 3.5
_AOCV_FOCUS_MATCH_MIN_FRAMES = 3
_AOCV_FOCUS_MATCH_MAX_FRAMES = 8
_AOCV_ANALOG_MATCH_FRAMES = 6
_AOCV_EXTRA_EVENT_RATIO = 0.25
_AOCV_ALIGN_MAX_FRAMES = 10

def _parse_fps(rate: Optional[str]) -> float:
    if not rate:
        return 0.0
    try:
        return float(Fraction(rate))
    except Exception:
        return 0.0

def _ffprobe_stream_info(path: str) -> Tuple[int, int, float]:
    cmd = [
        "ffprobe", "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=width,height,avg_frame_rate",
        "-of", "json", path
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"ffprobe failed: {proc.stderr.strip()}")
    payload = json.loads(proc.stdout or "{}")
    streams = payload.get("streams") or []
    if not streams:
        raise RuntimeError("ffprobe: no video streams")
    stream = streams[0]
    width = int(stream.get("width") or 0)
    height = int(stream.get("height") or 0)
    fps = _parse_fps(stream.get("avg_frame_rate"))
    return width, height, fps

def _scaled_dims(src_w: int, src_h: int) -> Tuple[int, int]:
    if src_w <= 0 or src_h <= 0:
        raise ValueError("invalid source dimensions")
    scale_w = min(_AOCV_SCALE_WIDTH, src_w)
    scale_h = int(round(src_h * scale_w / src_w))
    if scale_h % 2 != 0:
        scale_h -= 1
    scale_h = max(scale_h, 2)
    return scale_w, scale_h

def _iter_gray_frames(path: str, scale_w: int, scale_h: int, sample_fps: float):
    vf = f"fps={sample_fps},scale={scale_w}:{scale_h},format=gray"
    cmd = [
        "ffmpeg", "-v", "error", "-i", path,
        "-vf", vf, "-f", "rawvideo", "-pix_fmt", "gray", "-"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    frame_size = scale_w * scale_h
    try:
        while True:
            buf = proc.stdout.read(frame_size)
            if not buf or len(buf) < frame_size:
                break
            frame = np.frombuffer(buf, dtype=np.uint8).reshape((scale_h, scale_w))
            yield frame
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        ret = proc.wait()
        if ret != 0:
            raise RuntimeError("ffmpeg frame decode failed")

def _tile_bounds(height: int, width: int, rows: int, cols: int) -> List[Tuple[int, int, int, int]]:
    bounds = []
    tile_h = max(1, height // rows)
    tile_w = max(1, width // cols)
    for r in range(rows):
        y0 = r * tile_h
        y1 = height if r == rows - 1 else min(height, y0 + tile_h)
        for c in range(cols):
            x0 = c * tile_w
            x1 = width if c == cols - 1 else min(width, x0 + tile_w)
            bounds.append((y0, y1, x0, x1))
    return bounds

def _gradient_magnitude(gray: np.ndarray) -> np.ndarray:
    gx = np.abs(np.diff(gray, axis=1))
    gy = np.abs(np.diff(gray, axis=0))
    h = min(gx.shape[0], gy.shape[0])
    w = min(gx.shape[1], gy.shape[1])
    return gx[:h, :w] + gy[:h, :w]

def _gradient_energy(gray: np.ndarray) -> np.ndarray:
    g = gray.astype(np.float32)
    gx = np.diff(g, axis=1)
    gy = np.diff(g, axis=0)
    h = min(gx.shape[0], gy.shape[0])
    w = min(gx.shape[1], gy.shape[1])
    return gx[:h, :w] * gx[:h, :w] + gy[:h, :w] * gy[:h, :w]

def _laplacian(gray: np.ndarray) -> np.ndarray:
    if gray.shape[0] < 3 or gray.shape[1] < 3:
        return np.empty((0, 0), dtype=np.float32)
    g = gray.astype(np.float32)
    center = g[1:-1, 1:-1]
    return (-4.0 * center
            + g[1:-1, :-2]
            + g[1:-1, 2:]
            + g[:-2, 1:-1]
            + g[2:, 1:-1])

def _metric_array(gray: np.ndarray) -> Tuple[str, np.ndarray]:
    if _AOCV_SHARPNESS_METRIC == "laplacian_var":
        lap = _laplacian(gray)
        if lap.size:
            return "laplacian_var", lap
    if _AOCV_SHARPNESS_METRIC == "tenengrad":
        return "tenengrad", _gradient_energy(gray)
    return "gradient_mean", _gradient_magnitude(gray)

def _tile_metric_value(tile: np.ndarray, metric: str) -> float:
    if tile.size == 0:
        return 0.0
    if metric == "laplacian_var":
        return float(np.var(tile))
    return float(np.mean(tile))

def _select_tiles(path: str, scale_w: int, scale_h: int, sample_fps: float) -> Tuple[List[int], Dict[str, Any]]:
    img_bounds = _tile_bounds(scale_h, scale_w, _AOCV_TILE_ROWS, _AOCV_TILE_COLS)
    metric_bounds: List[Tuple[int, int, int, int]] = []
    metric_kind: Optional[str] = None
    tile_count = len(img_bounds)
    sums = np.zeros(tile_count, dtype=np.float64)
    sums_sq = np.zeros(tile_count, dtype=np.float64)
    sat_hits = np.zeros(tile_count, dtype=np.float64)
    frames = 0

    for frame in _iter_gray_frames(path, scale_w, scale_h, sample_fps):
        kind, metric = _metric_array(frame)
        if metric_kind is None:
            metric_kind = kind
            metric_bounds = _tile_bounds(metric.shape[0], metric.shape[1], _AOCV_TILE_ROWS, _AOCV_TILE_COLS)
        for idx, (gy0, gy1, gx0, gx1) in enumerate(metric_bounds):
            tile_val = _tile_metric_value(metric[gy0:gy1, gx0:gx1], metric_kind)
            sums[idx] += tile_val
            sums_sq[idx] += tile_val * tile_val
            iy0, iy1, ix0, ix1 = img_bounds[idx]
            tile_img = frame[iy0:iy1, ix0:ix1]
            if tile_img.size:
                sat_ratio = float(np.mean((tile_img < 5) | (tile_img > 250)))
                if sat_ratio > _AOCV_TILE_SAT_THRESHOLD:
                    sat_hits[idx] += 1
        frames += 1

    if frames == 0:
        return [], {"error": "no frames decoded"}

    means = sums / frames
    sat_ratio = sat_hits / frames
    eligible = [i for i in range(tile_count) if sat_ratio[i] <= _AOCV_TILE_SAT_THRESHOLD and means[i] > 0.0]
    if not eligible:
        eligible = [i for i in range(tile_count) if means[i] > 0.0]
    if not eligible:
        eligible = list(range(tile_count))

    mean_threshold = float(np.median([means[i] for i in eligible])) if eligible else 0.0
    eligible.sort(key=lambda i: means[i], reverse=True)
    max_tiles = min(12, len(eligible))
    min_tiles = min(8, len(eligible))
    selected = eligible[:max_tiles]
    if len(selected) < min_tiles:
        selected = eligible[:min_tiles]
    if len(selected) < 4:
        fallback = sorted(range(tile_count), key=lambda i: means[i], reverse=True)
        selected = fallback[: max(4, len(fallback))]

    diag = {
        "frames_sampled": frames,
        "tile_rows": _AOCV_TILE_ROWS,
        "tile_cols": _AOCV_TILE_COLS,
        "tile_count": tile_count,
        "selected_tiles": selected,
        "mean_threshold": mean_threshold,
        "sat_threshold": _AOCV_TILE_SAT_THRESHOLD,
    }
    if metric_kind is not None:
        diag["sharpness_metric"] = metric_kind
    return selected, diag

def _select_noise_tiles(path: str, scale_w: int, scale_h: int, sample_fps: float) -> Tuple[List[int], Dict[str, Any]]:
    img_bounds = _tile_bounds(scale_h, scale_w, _AOCV_TILE_ROWS, _AOCV_TILE_COLS)
    metric_bounds: List[Tuple[int, int, int, int]] = []
    metric_kind: Optional[str] = None
    tile_count = len(img_bounds)
    sums = np.zeros(tile_count, dtype=np.float64)
    means_sum = np.zeros(tile_count, dtype=np.float64)
    sat_hits = np.zeros(tile_count, dtype=np.float64)
    frames = 0

    for frame in _iter_gray_frames(path, scale_w, scale_h, sample_fps):
        kind, metric = _metric_array(frame)
        if metric_kind is None:
            metric_kind = kind
            metric_bounds = _tile_bounds(metric.shape[0], metric.shape[1], _AOCV_TILE_ROWS, _AOCV_TILE_COLS)
        for idx, (gy0, gy1, gx0, gx1) in enumerate(metric_bounds):
            tile_val = _tile_metric_value(metric[gy0:gy1, gx0:gx1], metric_kind)
            sums[idx] += tile_val
            iy0, iy1, ix0, ix1 = img_bounds[idx]
            tile_img = frame[iy0:iy1, ix0:ix1]
            if tile_img.size:
                means_sum[idx] += float(np.mean(tile_img))
                sat_ratio = float(np.mean(tile_img > 250))
                if sat_ratio > _AOCV_TILE_SAT_THRESHOLD:
                    sat_hits[idx] += 1
        frames += 1

    if frames == 0:
        return [], {"error": "no frames decoded"}

    means = sums / frames
    mean_intensity = means_sum / frames
    sat_ratio = sat_hits / frames
    eligible = [
        i for i in range(tile_count)
        if sat_ratio[i] <= _AOCV_TILE_SAT_THRESHOLD
        and _AOCV_ANALOG_MEAN_MIN <= mean_intensity[i] <= _AOCV_ANALOG_MEAN_MAX
    ]
    if len(eligible) < 4:
        low_q = float(np.quantile(mean_intensity, 0.1))
        high_q = float(np.quantile(mean_intensity, 0.9))
        eligible = [
            i for i in range(tile_count)
            if sat_ratio[i] <= _AOCV_TILE_SAT_THRESHOLD
            and low_q <= mean_intensity[i] <= high_q
        ]
    if not eligible:
        eligible = list(range(tile_count))

    eligible.sort(key=lambda i: means[i])
    max_tiles = min(12, len(eligible))
    min_tiles = min(8, len(eligible))
    selected = eligible[:max_tiles]
    if len(selected) < min_tiles:
        selected = eligible[:min_tiles]
    if len(selected) < 4:
        selected = eligible[: max(4, len(eligible))]

    mean_threshold = float(np.median([means[i] for i in eligible])) if eligible else 0.0
    diag = {
        "frames_sampled": frames,
        "tile_rows": _AOCV_TILE_ROWS,
        "tile_cols": _AOCV_TILE_COLS,
        "tile_count": tile_count,
        "selected_tiles": selected,
        "mean_threshold": mean_threshold,
        "mean_intensity_min": float(np.min(mean_intensity)) if mean_intensity.size else None,
        "mean_intensity_max": float(np.max(mean_intensity)) if mean_intensity.size else None,
        "sat_threshold": _AOCV_TILE_SAT_THRESHOLD,
    }
    if metric_kind is not None:
        diag["sharpness_metric"] = metric_kind
    return selected, diag

def _sharpness_signal(path: str, scale_w: int, scale_h: int, sample_fps: float, selected_tiles: List[int]) -> Tuple[np.ndarray, Dict[str, Any]]:
    if not selected_tiles:
        return np.array([]), {"error": "no tiles selected"}
    metric_bounds: List[Tuple[int, int, int, int]] = []
    metric_kind: Optional[str] = None
    tile_series: List[List[float]] = [[] for _ in selected_tiles]
    for frame in _iter_gray_frames(path, scale_w, scale_h, sample_fps):
        kind, metric = _metric_array(frame)
        if metric_kind is None:
            metric_kind = kind
            metric_bounds = _tile_bounds(metric.shape[0], metric.shape[1], _AOCV_TILE_ROWS, _AOCV_TILE_COLS)
        for pos, idx in enumerate(selected_tiles):
            gy0, gy1, gx0, gx1 = metric_bounds[idx]
            tile_series[pos].append(_tile_metric_value(metric[gy0:gy1, gx0:gx1], metric_kind or "gradient_mean"))

    if not tile_series or not tile_series[0]:
        return np.array([]), {"error": "no tile signal"}

    mat = np.asarray(tile_series, dtype=np.float64).T
    aggregate = _AOCV_TILE_AGGREGATE
    if aggregate == "pca1" and mat.shape[1] >= 2:
        mat = mat - np.mean(mat, axis=0, keepdims=True)
        u, s, _ = np.linalg.svd(mat, full_matrices=False)
        signal = u[:, 0] * s[0]
    else:
        signal = np.mean(mat, axis=1)
        aggregate = "mean"

    diag = {"frames_used": int(mat.shape[0]), "aggregate": aggregate}
    if metric_kind is not None:
        diag["sharpness_metric"] = metric_kind
    return np.array(signal, dtype=np.float64), diag

def _noise_variance_signal(path: str, scale_w: int, scale_h: int, sample_fps: float, selected_tiles: List[int]) -> Tuple[np.ndarray, Dict[str, Any]]:
    if not selected_tiles:
        return np.array([]), {"error": "no tiles selected"}
    img_bounds = _tile_bounds(scale_h, scale_w, _AOCV_TILE_ROWS, _AOCV_TILE_COLS)
    values: List[float] = []
    prev = None
    for frame in _iter_gray_frames(path, scale_w, scale_h, sample_fps):
        if prev is None:
            prev = frame
            continue
        per_tile = []
        for idx in selected_tiles:
            iy0, iy1, ix0, ix1 = img_bounds[idx]
            tile = frame[iy0:iy1, ix0:ix1]
            prev_tile = prev[iy0:iy1, ix0:ix1]
            if tile.size == 0:
                continue
            diff = tile.astype(np.float32) - prev_tile.astype(np.float32)
            mu = float(np.mean(diff))
            var = float(np.mean((diff - mu) ** 2))
            per_tile.append(var)
        values.append(float(np.median(per_tile)) if per_tile else 0.0)
        prev = frame

    if not values:
        return np.array([]), {"error": "no tile signal"}

    return np.array(values, dtype=np.float64), {"frames_used": len(values), "aggregate": "median_var", "mode": "temporal_diff"}

def _mean_intensity_signal(path: str, scale_w: int, scale_h: int, sample_fps: float, selected_tiles: List[int]) -> Tuple[np.ndarray, Dict[str, Any]]:
    if not selected_tiles:
        return np.array([]), {"error": "no tiles selected"}
    img_bounds = _tile_bounds(scale_h, scale_w, _AOCV_TILE_ROWS, _AOCV_TILE_COLS)
    values: List[float] = []
    for frame in _iter_gray_frames(path, scale_w, scale_h, sample_fps):
        per_tile = []
        for idx in selected_tiles:
            iy0, iy1, ix0, ix1 = img_bounds[idx]
            tile = frame[iy0:iy1, ix0:ix1]
            if tile.size == 0:
                continue
            per_tile.append(float(np.mean(tile)))
        values.append(float(np.median(per_tile)) if per_tile else 0.0)
    if not values:
        return np.array([]), {"error": "no tile signal"}
    return np.array(values, dtype=np.float64), {"frames_used": len(values), "aggregate": "median_mean", "mode": "intensity"}

def _global_mean_signal(path: str, scale_w: int, scale_h: int, sample_fps: float) -> Tuple[np.ndarray, Dict[str, Any]]:
    values: List[float] = []
    for frame in _iter_gray_frames(path, scale_w, scale_h, sample_fps):
        if frame.size == 0:
            continue
        values.append(float(np.mean(frame)))
    if not values:
        return np.array([]), {"error": "no frames decoded"}
    return np.array(values, dtype=np.float64), {"frames_used": len(values), "aggregate": "global_mean", "mode": "intensity_full"}

def _detrend_window(rate_hz: Optional[float], frame_ms: float) -> int:
    if rate_hz and rate_hz > 0 and frame_ms > 0:
        sample_fps = 1000.0 / frame_ms
        window = int(round(sample_fps * (_AOCV_DETREND_PERIODS / rate_hz)))
        window = max(_AOCV_DETREND_MIN, min(_AOCV_DETREND_MAX, window))
        if window % 2 == 0:
            window += 1
        return window
    return 31

def _detrend_signal(signal: np.ndarray, window: int = 31) -> np.ndarray:
    if signal.size == 0:
        return signal
    if signal.size < window:
        return signal - np.mean(signal)
    kernel = np.ones(window, dtype=np.float64) / float(window)
    smooth = np.convolve(signal, kernel, mode="same")
    return signal - smooth

def _normalize_signal(signal: np.ndarray) -> np.ndarray:
    if signal.size == 0:
        return signal
    mean = float(np.mean(signal))
    std = float(np.std(signal))
    if std < _AOCV_SIGNAL_EPS:
        return signal - mean
    return (signal - mean) / std

def _smooth_signal(signal: np.ndarray, window: int) -> np.ndarray:
    if signal.size == 0 or window <= 1:
        return signal
    if signal.size < window:
        return signal
    kernel = np.ones(window, dtype=np.float64) / float(window)
    return np.convolve(signal, kernel, mode="same")

def _expected_focus_signal(events: List[Dict[str, Any]], frame_count: int, frame_ms: float, ramp_ms: int) -> np.ndarray:
    if not events or frame_count <= 0:
        return np.zeros(frame_count, dtype=np.float64)
    ev = sorted(events, key=lambda e: e["t_ms"])
    times = [int(e["t_ms"]) for e in ev]
    codes = [int(e["focus_code"]) for e in ev]
    out = np.zeros(frame_count, dtype=np.float64)
    idx = 0
    for i in range(frame_count):
        t_ms = i * frame_ms
        while idx + 1 < len(times) and t_ms >= times[idx + 1]:
            idx += 1
        if idx == 0:
            out[i] = codes[0]
            continue
        dt = t_ms - times[idx]
        if ramp_ms > 0 and dt < ramp_ms:
            prev_code = codes[idx - 1]
            cur_code = codes[idx]
            out[i] = prev_code + (cur_code - prev_code) * (dt / float(ramp_ms))
        else:
            out[i] = codes[idx]
    return out

def _best_lag_corr(obs: np.ndarray, exp: np.ndarray, max_lag: int, *, signed: bool = False) -> Tuple[float, int]:
    best = -1.0 if signed else 0.0
    best_lag = 0
    for lag in range(-max_lag, max_lag + 1):
        if lag < 0:
            x = exp[-lag:]
            y = obs[: x.size]
        elif lag > 0:
            x = exp[:-lag]
            y = obs[lag:]
        else:
            x = exp
            y = obs
        if x.size < 2 or y.size < 2:
            continue
        denom = (np.linalg.norm(x) * np.linalg.norm(y))
        if denom < _AOCV_SIGNAL_EPS:
            continue
        corr = float(np.dot(x, y) / denom)
        if signed:
            if corr > best:
                best = corr
                best_lag = lag
        else:
            if abs(corr) > abs(best):
                best = corr
                best_lag = lag
    return best, best_lag

def _shuffle_p_value(
    obs: np.ndarray,
    exp: np.ndarray,
    max_lag: int,
    shuffles: int,
    *,
    signed: bool = False
) -> float:
    if obs.size < 2 or exp.size < 2:
        return 1.0
    rng = random.Random(1337)
    observed, _ = _best_lag_corr(obs, exp, max_lag, signed=signed)
    if signed and observed <= 0.0:
        return 1.0
    target = observed if signed else abs(observed)
    hits = 0
    for _ in range(shuffles):
        shift = rng.randrange(1, exp.size)
        shifted = np.roll(exp, shift)
        corr, _ = _best_lag_corr(obs, shifted, max_lag, signed=signed)
        if signed:
            if corr >= target:
                hits += 1
        else:
            if abs(corr) >= target:
                hits += 1
    return (hits + 1) / float(shuffles + 1)

def _event_required_count(events_tested: int) -> int:
    if events_tested <= 0:
        return 0
    if events_tested <= 1:
        return 1
    if events_tested <= 4:
        return 2
    return max(3, int(math.ceil(0.4 * events_tested)))

def _event_window_frames(ramp_ms: int, frame_ms: float) -> int:
    if frame_ms <= 0:
        return _AOCV_EVENT_DUR_MIN_FRAMES
    base = int(round(ramp_ms / frame_ms)) if ramp_ms > 0 else _AOCV_EVENT_DUR_MIN_FRAMES
    return max(_AOCV_EVENT_DUR_MIN_FRAMES, min(_AOCV_EVENT_DUR_MAX_FRAMES, base))

def _event_p_value(aligned_deltas: List[float], shuffles: int) -> float:
    if len(aligned_deltas) < 2:
        return 1.0
    obs_mean = float(np.mean(aligned_deltas))
    if obs_mean <= 0.0:
        return 1.0
    n = len(aligned_deltas)
    if n <= 10:
        hits = 0
        total = 0
        for mask in range(1 << n):
            signed = [(aligned_deltas[i] if (mask >> i) & 1 else -aligned_deltas[i]) for i in range(n)]
            if float(np.mean(signed)) >= obs_mean:
                hits += 1
            total += 1
        return (hits + 1) / float(total + 1)
    rng = random.Random(1337)
    hits = 0
    for _ in range(shuffles):
        signed = [(d if rng.random() < 0.5 else -d) for d in aligned_deltas]
        if float(np.mean(signed)) >= obs_mean:
            hits += 1
    return (hits + 1) / float(shuffles + 1)

def _robust_threshold(values: np.ndarray, z: float) -> float:
    if values.size == 0:
        return 0.0
    median = float(np.median(values))
    mad = float(np.median(np.abs(values - median)))
    if mad > 0.0:
        return median + z * 1.4826 * mad
    mean = float(np.mean(values))
    std = float(np.std(values))
    return mean + z * std

def _match_window_frames(sample_fps: float) -> int:
    if sample_fps <= 0.0:
        return _AOCV_FOCUS_MATCH_MAX_FRAMES
    guess = int(round(sample_fps * 0.5))
    return max(_AOCV_FOCUS_MATCH_MIN_FRAMES, min(_AOCV_FOCUS_MATCH_MAX_FRAMES, guess))

def _detect_blind_events(
    signal: np.ndarray,
    frame_ms: float,
    *,
    min_separation_s: float,
    smooth_window: int,
    z_threshold: float,
    window_frames: Optional[int] = None
) -> Tuple[List[int], Dict[str, Any]]:
    if signal.size < 3 or frame_ms <= 0:
        return [], {"events_detected": 0, "threshold": None}
    smooth_window = max(1, int(smooth_window))
    smooth = _smooth_signal(signal, smooth_window)
    detection_mode = "diff"
    if window_frames is not None and window_frames > 1:
        w = int(window_frames)
        kernel = np.concatenate([
            -np.ones(w, dtype=np.float64) / float(w),
            np.ones(w, dtype=np.float64) / float(w),
        ])
        filt = np.convolve(smooth, kernel, mode="same")
        mag = np.abs(filt)
        detection_mode = "matched_step"
    else:
        diff = np.diff(smooth)
        mag = np.abs(diff)
    threshold = _robust_threshold(mag, z_threshold)
    candidates: List[Tuple[int, float]] = []
    start_idx = 1
    end_idx = mag.size - 1
    if window_frames is not None and window_frames > 1:
        start_idx = int(window_frames)
        end_idx = int(mag.size - window_frames)
    for i in range(start_idx, end_idx):
        if mag[i] >= threshold and mag[i] >= mag[i - 1] and mag[i] >= mag[i + 1]:
            candidates.append((i, float(mag[i])))
    min_sep_frames = max(1, int(round((min_separation_s * 1000.0) / frame_ms)))
    selected: List[int] = []
    for idx, _ in sorted(candidates, key=lambda item: item[1], reverse=True):
        if all(abs(idx - s) >= min_sep_frames for s in selected):
            selected.append(idx)
    selected.sort()
    if detection_mode == "matched_step":
        events_ms = [int(round(idx * frame_ms)) for idx in selected]
    else:
        events_ms = [int(round((idx + 1) * frame_ms)) for idx in selected]
    diag = {
        "events_detected": len(events_ms),
        "candidates": len(candidates),
        "threshold": threshold,
        "min_separation_frames": min_sep_frames,
        "smooth_window": smooth_window,
        "detection_mode": detection_mode,
        "window_frames": int(window_frames) if window_frames is not None else None,
    }
    return events_ms, diag

def _match_events(
    expected_ms: List[int],
    observed_ms: List[int],
    *,
    max_delta_ms: float
) -> Tuple[int, int]:
    if not expected_ms or not observed_ms:
        return 0, len(observed_ms)
    expected_sorted = sorted(expected_ms)
    observed_sorted = sorted(observed_ms)
    used = set()
    matched = 0
    for exp in expected_sorted:
        best_idx = None
        best_delta = None
        for i, obs in enumerate(observed_sorted):
            if i in used:
                continue
            delta = abs(obs - exp)
            if delta <= max_delta_ms and (best_delta is None or delta < best_delta):
                best_idx = i
                best_delta = delta
        if best_idx is not None:
            used.add(best_idx)
            matched += 1
    extra = len(observed_sorted) - len(used)
    return matched, extra

def _best_alignment(
    expected_ms: List[int],
    observed_ms: List[int],
    *,
    frame_ms: float,
    match_window_frames: int,
    max_offset_frames: int
) -> Tuple[int, int, int]:
    if not expected_ms or not observed_ms or frame_ms <= 0:
        return 0, 0, len(observed_ms)
    best_offset = 0
    best_matched = -1
    best_extra = 1_000_000
    for offset in range(-max_offset_frames, max_offset_frames + 1):
        shift_ms = offset * frame_ms
        shifted = [int(round(t + shift_ms)) for t in expected_ms if (t + shift_ms) >= 0]
        matched, extra = _match_events(
            shifted,
            observed_ms,
            max_delta_ms=match_window_frames * frame_ms
        )
        if matched > best_matched:
            best_offset, best_matched, best_extra = offset, matched, extra
            continue
        if matched == best_matched:
            if extra < best_extra:
                best_offset, best_matched, best_extra = offset, matched, extra
                continue
            if extra == best_extra and abs(offset) < abs(best_offset):
                best_offset, best_matched, best_extra = offset, matched, extra
    return best_offset, best_matched, best_extra

def _observed_decision(
    *,
    expected_events: int,
    matched_events: int,
    extra_events: int,
    duration_ms: float
) -> Tuple[str, int, Optional[int]]:
    if expected_events <= 0:
        return "inconclusive", 0, None
    short_clip = duration_ms < 30_000.0
    required = int(math.ceil((0.8 if short_clip else 0.6) * expected_events))
    extra_limit = int(math.floor(_AOCV_EXTRA_EVENT_RATIO * expected_events))
    extra_ok = True if expected_events < 4 else (extra_events <= extra_limit)
    if matched_events >= required and extra_ok:
        return "true", required, extra_limit
    return "false", required, extra_limit

def _analog_event_window_deltas(
    signal: np.ndarray,
    frame_ms: float,
    events: List[Dict[str, Any]],
    ramp_ms: int,
    lag_frames: int,
) -> Tuple[List[float], Dict[str, Any]]:
    if signal.size < 2 or frame_ms <= 0:
        return [], {"events_declared": len(events), "events_tested": 0}
    ev = sorted(events, key=lambda e: e["t_ms"])
    dur_frames = _event_window_frames(ramp_ms, frame_ms)
    pre_frames = dur_frames
    post_frames = dur_frames
    deltas: List[float] = []
    for e in ev:
        idx = int(round(e["t_ms"] / frame_ms)) + int(lag_frames)
        if idx <= 0 or idx >= signal.size:
            continue
        pre_start = max(0, idx - pre_frames)
        pre_end = min(idx, signal.size)
        dur_end = min(signal.size, idx + dur_frames)
        if pre_end <= pre_start or dur_end <= idx:
            continue
        pre = signal[pre_start:pre_end]
        during = signal[idx:dur_end]
        delta = float(np.mean(during) - np.mean(pre))
        post_end = min(signal.size, dur_end + post_frames)
        if post_end > dur_end:
            post = signal[dur_end:post_end]
            if post.size:
                delta = float(np.mean(during) - 0.5 * (np.mean(pre) + np.mean(post)))
        deltas.append(delta)
    diag = {
        "events_declared": len(events),
        "events_tested": len(deltas),
        "event_window_frames": {"pre": pre_frames, "during": dur_frames, "post": post_frames},
        "event_lag_frames": int(lag_frames),
    }
    return deltas, diag

def _event_window_deltas(
    signal: np.ndarray,
    frame_ms: float,
    events: List[Dict[str, Any]],
    ramp_ms: int,
    lag_frames: int,
) -> Tuple[List[float], Dict[str, Any]]:
    if signal.size < 2 or frame_ms <= 0:
        return [], {"events_declared": len(events), "events_tested": 0}
    ev = sorted(events, key=lambda e: e["t_ms"])
    dur_frames = _event_window_frames(ramp_ms, frame_ms)
    pre_frames = dur_frames
    post_frames = dur_frames
    aligned_deltas: List[float] = []
    for i in range(1, len(ev)):
        prev_code = int(ev[i - 1]["focus_code"])
        cur_code = int(ev[i]["focus_code"])
        direction = 1 if cur_code > prev_code else -1 if cur_code < prev_code else 0
        if direction == 0:
            continue
        idx = int(round(ev[i]["t_ms"] / frame_ms)) + int(lag_frames)
        if idx <= 0 or idx >= signal.size:
            continue
        pre_start = max(0, idx - pre_frames)
        pre_end = min(idx, signal.size)
        dur_end = min(signal.size, idx + dur_frames)
        if pre_end <= pre_start or dur_end <= idx:
            continue
        pre = signal[pre_start:pre_end]
        during = signal[idx:dur_end]
        delta = float(np.mean(during) - np.mean(pre))
        post_end = min(signal.size, dur_end + post_frames)
        if post_end > dur_end:
            post = signal[dur_end:post_end]
            if post.size:
                delta = float(np.mean(during) - 0.5 * (np.mean(pre) + np.mean(post)))
        aligned_deltas.append(delta * direction)
    diag = {
        "events_declared": len(events),
        "events_tested": len(aligned_deltas),
        "event_window_frames": {"pre": pre_frames, "during": dur_frames, "post": post_frames},
        "event_lag_frames": int(lag_frames),
    }
    return aligned_deltas, diag

def _parse_analog_events(analog: Dict[str, Any]) -> List[Dict[str, int]]:
    events = analog.get("events")
    if not isinstance(events, list):
        return []
    parsed: List[Dict[str, int]] = []
    baseline_exp = None
    baseline_iso = None
    for e in events:
        if not isinstance(e, dict):
            continue
        t_ms = e.get("t_ms")
        if not isinstance(t_ms, int) or t_ms < 0:
            continue
        exp = e.get("exposure_ns")
        iso = e.get("iso")
        if baseline_exp is None and isinstance(exp, (int, float)) and exp > 0:
            baseline_exp = float(exp)
        if baseline_iso is None and isinstance(iso, (int, float)) and iso > 0:
            baseline_iso = float(iso)
        scale_bps = e.get("scale_bps")
        if isinstance(scale_bps, (int, float)):
            scale_bps = int(round(scale_bps))
        else:
            scale_pct = e.get("scale_pct")
            if isinstance(scale_pct, (int, float)):
                scale_bps = int(round(float(scale_pct) * 100.0))
            else:
                if baseline_exp and isinstance(exp, (int, float)):
                    scale_bps = int(round((float(exp) / baseline_exp - 1.0) * 10_000.0))
                elif baseline_iso and isinstance(iso, (int, float)):
                    scale_bps = int(round((float(iso) / baseline_iso - 1.0) * 10_000.0))
        if scale_bps is None:
            continue
        magnitude_bps = None
        iso_bps = None
        exposure_bps = None
        if baseline_exp and baseline_iso:
            exp_ratio = float(exp) / baseline_exp if isinstance(exp, (int, float)) and exp > 0 else None
            iso_ratio = float(iso) / baseline_iso if isinstance(iso, (int, float)) and iso > 0 else None
            if exp_ratio is not None or iso_ratio is not None:
                parts = []
                if exp_ratio is not None:
                    parts.append(abs(exp_ratio - 1.0))
                    exposure_bps = int(round((exp_ratio - 1.0) * 10_000.0))
                if iso_ratio is not None:
                    parts.append(abs(iso_ratio - 1.0))
                    iso_bps = int(round((iso_ratio - 1.0) * 10_000.0))
                if parts:
                    magnitude_bps = int(round((sum(parts) / len(parts)) * 10_000.0))
        parsed.append({
            "t_ms": int(t_ms),
            "scale_bps": int(scale_bps),
            "magnitude_bps": int(magnitude_bps if magnitude_bps is not None else abs(scale_bps)),
            "iso_bps": int(iso_bps) if iso_bps is not None else None,
            "exposure_bps": int(exposure_bps) if exposure_bps is not None else None,
        })
    parsed.sort(key=lambda item: item["t_ms"])
    return parsed

def _expected_analog_signal(
    events: List[Dict[str, int]],
    frame_count: int,
    frame_ms: float,
    ramp_ms: int,
    *,
    use_magnitude: bool = True
) -> np.ndarray:
    if not events or frame_count <= 0 or frame_ms <= 0:
        return np.zeros(frame_count, dtype=np.float64)
    out = np.zeros(frame_count, dtype=np.float64)
    ev = sorted(events, key=lambda e: e["t_ms"])
    times = [int(e["t_ms"]) for e in ev]
    if use_magnitude:
        values = [float(e.get("magnitude_bps", abs(e["scale_bps"]))) for e in ev]
    else:
        values = [float(e["scale_bps"]) for e in ev]
    ramp_ms = max(0, int(ramp_ms))

    def idx_for(t_ms: int) -> int:
        return int(round(t_ms / frame_ms))

    first_idx = max(0, idx_for(times[0]))
    if first_idx > 0:
        out[: min(first_idx, frame_count)] = values[0]
    prev_t = times[0]
    prev_v = values[0]
    start_idx = min(first_idx, frame_count)

    for t_ms, v in zip(times[1:], values[1:]):
        cur_idx = max(0, idx_for(t_ms))
        ramp_start_t = max(prev_t, t_ms - ramp_ms)
        ramp_start_idx = max(0, idx_for(ramp_start_t))

        if ramp_start_idx > start_idx:
            out[start_idx: min(ramp_start_idx, frame_count)] = prev_v

        ramp_end_idx = min(cur_idx, frame_count)
        if ramp_end_idx > ramp_start_idx:
            span = max(1, ramp_end_idx - ramp_start_idx)
            for i in range(ramp_start_idx, ramp_end_idx):
                frac = (i - ramp_start_idx) / float(span)
                out[i] = prev_v + (v - prev_v) * frac

        start_idx = min(max(cur_idx, ramp_start_idx), frame_count)
        prev_t = t_ms
        prev_v = v

    if start_idx < frame_count:
        out[start_idx:] = prev_v
    return out

def _write_analog_csv(
    path: str,
    *,
    frame_ms: float,
    signal_nv: np.ndarray,
    signal_int: np.ndarray,
    signal_global: np.ndarray,
    pulse_intervals: List[Tuple[int, int]],
    events: List[Dict[str, int]],
    ramp_ms: int
) -> None:
    rows = []
    frame_count = max(signal_global.size, signal_int.size, signal_nv.size + 1)
    for idx in range(frame_count):
        t_ms = idx * frame_ms
        nv = None
        if idx > 0 and (idx - 1) < signal_nv.size:
            nv = float(signal_nv[idx - 1])
        mean_int = float(signal_int[idx]) if idx < signal_int.size else None
        mean_global = float(signal_global[idx]) if idx < signal_global.size else None
        expected = 0
        if pulse_intervals:
            expected = 1 if any(start <= t_ms <= end for start, end in pulse_intervals) else 0
        else:
            for ev in events:
                start = int(ev["t_ms"])
                end = start + max(0, int(ramp_ms))
                if start <= t_ms <= end:
                    expected = 1
                    break
        rows.append((idx, int(round(t_ms)), mean_global, mean_int, nv, expected))

    if not rows:
        return
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "frame_idx",
            "t_ms",
            "global_mean",
            "mean_intensity",
            "noise_variance",
            "expected_pulse_raw",
        ])
        writer.writerows(rows)

def _verify_analog(
    path: str,
    analog: Dict[str, Any],
    params: Dict[str, Any],
    scale_w: int,
    scale_h: int,
    sample_fps: float,
    frame_ms: float,
    analog_csv_path: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    events = _parse_analog_events(analog)
    if not events:
        return {"observed": "inconclusive", "reason": "analog events missing"}, {"error": "no_analog_events"}
    raw_events = events
    zero_events = sum(1 for e in events if abs(int(e.get("scale_bps", 0))) <= 1)
    pulse_mode = zero_events > 1 and zero_events >= max(2, len(events) // 3)
    pulse_intervals: List[Tuple[int, int]] = []
    if pulse_mode:
        non_zero = [e for e in events if abs(int(e.get("scale_bps", 0))) > 1]
        if not non_zero:
            return {
                "observed": "inconclusive",
                "reason": "analog events missing after pulse filter"
            }, {"error": "no_pulse_events"}
        zero_times = [int(e["t_ms"]) for e in events if abs(int(e.get("scale_bps", 0))) <= 1]
        zero_times.sort()
        for e in non_zero:
            start = int(e["t_ms"])
            end = None
            for z in zero_times:
                if z > start:
                    end = z
                    break
            if end is None:
                end = start
            pulse_intervals.append((start, end))
        events = non_zero

    ramp_ms = 500
    analog_params = analog.get("parameters") if isinstance(analog.get("parameters"), dict) else {}
    if isinstance(analog_params.get("ramp_ms"), int):
        ramp_ms = int(analog_params.get("ramp_ms"))
    elif isinstance(params.get("analog_ramp_ms"), int):
        ramp_ms = int(params.get("analog_ramp_ms"))

    rate_hz = None
    if isinstance(analog_params.get("rate_hz_milli"), (int, float)):
        rate_hz = float(analog_params.get("rate_hz_milli")) / 1000.0
    elif isinstance(analog_params.get("frequency_hz"), (int, float)):
        rate_hz = float(analog_params.get("frequency_hz"))
    elif isinstance(params.get("analog_rate_hz_milli"), (int, float)):
        rate_hz = float(params.get("analog_rate_hz_milli")) / 1000.0
    elif isinstance(params.get("analog_frequency_hz"), (int, float)):
        rate_hz = float(params.get("analog_frequency_hz"))

    tiles, tile_diag = _select_noise_tiles(path, scale_w, scale_h, sample_fps)
    expected_ms = [int(e["t_ms"]) for e in events]

    def eval_signal(
        signal: np.ndarray,
        signal_label: str,
        signal_diag: Dict[str, Any]
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        if signal.size < 4:
            return None
        detrend_window = _detrend_window(rate_hz, frame_ms)
        obs = _normalize_signal(_detrend_signal(signal, detrend_window))
        smooth_window = max(3, min(9, int(round(max(ramp_ms, 1) / frame_ms)))) if frame_ms > 0 else 3
        window_frames = _event_window_frames(ramp_ms, frame_ms)
        detected_ms, detect_diag = _detect_blind_events(
            obs,
            frame_ms,
            min_separation_s=_AOCV_EVENT_MIN_SEPARATION_S,
            smooth_window=smooth_window,
            z_threshold=_AOCV_EVENT_Z_THRESHOLD,
            window_frames=window_frames
        )
        aligned_offset, matched, extra = _best_alignment(
            expected_ms,
            detected_ms,
            frame_ms=frame_ms,
            match_window_frames=_AOCV_ANALOG_MATCH_FRAMES,
            max_offset_frames=_AOCV_ALIGN_MAX_FRAMES
        )
        if pulse_mode and pulse_intervals:
            shift_ms = aligned_offset * frame_ms
            window_ms = _AOCV_ANALOG_MATCH_FRAMES * frame_ms
            used = set()
            matched = 0
            for start, end in pulse_intervals:
                s = start + shift_ms - window_ms
                e = end + shift_ms + window_ms
                best_idx = None
                best_delta = None
                for i, obs_ms in enumerate(detected_ms):
                    if i in used:
                        continue
                    if s <= obs_ms <= e:
                        delta = min(abs(obs_ms - (start + shift_ms)), abs(obs_ms - (end + shift_ms)))
                        if best_delta is None or delta < best_delta:
                            best_delta = delta
                            best_idx = i
                if best_idx is not None:
                    used.add(best_idx)
                    matched += 1
            extra = len(detected_ms) - len(used)
        observed, required, extra_limit = _observed_decision(
            expected_events=len(expected_ms),
            matched_events=matched,
            extra_events=extra,
            duration_ms=signal.size * frame_ms
        )
        result = {
            "observed": observed,
            "expected_events": len(expected_ms),
            "expected_events_raw": len(raw_events),
            "pulse_mode": pulse_mode,
            "matched_events": matched,
            "extra_events": extra,
            "detected_events": len(detected_ms),
            "required_matches": required,
            "extra_event_limit": extra_limit,
            "match_window_frames": _AOCV_ANALOG_MATCH_FRAMES,
            "detect_window_frames": window_frames,
            "aligned_offset_frames": aligned_offset,
            "aligned_offset_ms": int(round(aligned_offset * frame_ms)),
            "signal_mode": signal_label,
            "detrend_window": detrend_window,
            "ramp_ms": ramp_ms,
        }
        diag = {}
        diag["pulse_mode"] = pulse_mode
        diag["events_raw"] = len(raw_events)
        diag["events_used"] = len(events)
        diag.update(tile_diag)
        diag.update(signal_diag)
        diag.update(detect_diag)
        if rate_hz is not None:
            diag["rate_hz"] = rate_hz
        return result, diag

    def eval_window_test(
        signal: np.ndarray,
        signal_label: str,
        signal_diag: Dict[str, Any]
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        if signal.size < 4 or frame_ms <= 0:
            return None
        frame_count = int(signal.size)
        prefix = np.zeros(frame_count + 1, dtype=np.float64)
        prefix[1:] = np.cumsum(signal)

        def mean_range(start: int, end: int) -> Optional[float]:
            if end <= start:
                return None
            start = max(0, min(start, frame_count))
            end = max(0, min(end, frame_count))
            if end <= start:
                return None
            return float((prefix[end] - prefix[start]) / (end - start))

        event_spans: List[Tuple[int, int]] = []
        if pulse_intervals:
            for start_ms, end_ms in pulse_intervals:
                start_idx = int(round(start_ms / frame_ms))
                end_idx = int(round(end_ms / frame_ms))
                if end_idx <= start_idx:
                    end_idx = start_idx + _event_window_frames(ramp_ms, frame_ms)
                event_spans.append((start_idx, end_idx))
        else:
            dur_frames = _event_window_frames(ramp_ms, frame_ms)
            for e in events:
                idx = int(round(e["t_ms"] / frame_ms))
                event_spans.append((idx, idx + dur_frames))

        deltas: List[float] = []
        for start_idx, end_idx in event_spans:
            span = max(1, end_idx - start_idx)
            pre_start = start_idx - span
            post_end = end_idx + span
            if pre_start < 0 or post_end > frame_count:
                continue
            pre = mean_range(pre_start, start_idx)
            during = mean_range(start_idx, end_idx)
            post = mean_range(end_idx, post_end)
            if pre is None or during is None or post is None:
                continue
            deltas.append(float(during - 0.5 * (pre + post)))

        if not deltas:
            return None

        rng = random.Random(1337)
        span_choices = [max(1, end - start) for start, end in event_spans] or [1]
        null_abs: List[float] = []
        max_samples = min(200, frame_count)
        for _ in range(max_samples):
            span = rng.choice(span_choices)
            if frame_count <= span * 3:
                break
            start_idx = rng.randint(span, frame_count - span * 2)
            end_idx = start_idx + span
            pre = mean_range(start_idx - span, start_idx)
            during = mean_range(start_idx, end_idx)
            post = mean_range(end_idx, end_idx + span)
            if pre is None or during is None or post is None:
                continue
            null_abs.append(abs(during - 0.5 * (pre + post)))

        if not null_abs:
            return None

        null_mean = float(np.mean(null_abs))
        null_std = float(np.std(null_abs))
        threshold = float(np.quantile(null_abs, 0.9))
        confirmed = sum(1 for d in deltas if abs(d) >= threshold)
        observed, required, extra_limit = _observed_decision(
            expected_events=len(event_spans),
            matched_events=confirmed,
            extra_events=0,
            duration_ms=signal.size * frame_ms
        )
        result = {
            "observed": observed,
            "expected_events": len(event_spans),
            "expected_events_raw": len(raw_events),
            "pulse_mode": pulse_mode,
            "matched_events": confirmed,
            "extra_events": 0,
            "detected_events": confirmed,
            "required_matches": required,
            "extra_event_limit": extra_limit,
            "match_window_frames": None,
            "detect_window_frames": None,
            "aligned_offset_frames": 0,
            "aligned_offset_ms": 0,
            "signal_mode": signal_label,
            "detrend_window": None,
            "ramp_ms": ramp_ms,
        }
        diag = {}
        diag["pulse_mode"] = pulse_mode
        diag["events_raw"] = len(raw_events)
        diag["events_used"] = len(event_spans)
        diag.update(signal_diag)
        diag["window_threshold"] = threshold
        diag["window_null_mean"] = null_mean
        diag["window_null_std"] = null_std
        diag["window_delta_mean"] = float(np.mean(deltas))
        diag["window_delta_median"] = float(np.median(deltas))
        diag["window_confirmed"] = confirmed
        return result, diag

    signal_nv, sig_nv = _noise_variance_signal(path, scale_w, scale_h, sample_fps, tiles)
    signal_int, sig_int = _mean_intensity_signal(path, scale_w, scale_h, sample_fps, tiles)
    signal_global, sig_global = _global_mean_signal(path, scale_w, scale_h, sample_fps)
    if analog_csv_path:
        _write_analog_csv(
            analog_csv_path,
            frame_ms=frame_ms,
            signal_nv=signal_nv,
            signal_int=signal_int,
            signal_global=signal_global,
            pulse_intervals=pulse_intervals,
            events=events,
            ramp_ms=ramp_ms
        )
    candidates = []
    nv_eval = eval_signal(signal_nv, "noise_variance", sig_nv)
    if nv_eval:
        candidates.append(nv_eval)
    int_eval = eval_signal(signal_int, "mean_intensity", sig_int)
    if int_eval:
        candidates.append(int_eval)
    global_eval = eval_signal(signal_global, "global_mean", sig_global)
    if global_eval:
        candidates.append(global_eval)
    window_eval = eval_window_test(signal_global, "global_mean_window", sig_global)
    if window_eval:
        candidates.append(window_eval)
    if not candidates:
        return {"observed": "inconclusive", "reason": "insufficient frames"}, {"frames": 0}

    def score(item: Tuple[Dict[str, Any], Dict[str, Any]]) -> Tuple[int, int]:
        res = item[0]
        observed = 1 if res.get("observed") == "true" else 0
        return (observed, int(res.get("matched_events", 0)))

    candidates.sort(key=score, reverse=True)
    result, diag = candidates[0]
    if len(candidates) > 1:
        diag["candidate_modes"] = [
            {
                "mode": c[0].get("signal_mode"),
                "observed": c[0].get("observed"),
                "matched_events": c[0].get("matched_events"),
                "detected_events": c[0].get("detected_events"),
                "aligned_offset_frames": c[0].get("aligned_offset_frames"),
            }
            for c in candidates
        ]
    return result, diag

def _verify_focus_fine(
    signal: np.ndarray,
    frame_ms: float,
    events: List[Dict[str, Any]],
    ramp_ms: int,
    rate_hz: Optional[float],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    detrend_window = _detrend_window(rate_hz, frame_ms)
    exp = _expected_focus_signal(events, signal.size, frame_ms, ramp_ms)
    obs = _normalize_signal(_detrend_signal(signal, detrend_window))
    exp = _normalize_signal(exp)
    obs_delta = np.abs(np.diff(obs))
    exp_delta = np.abs(np.diff(exp))
    exp_delta = np.where(exp_delta > 0.0, 1.0, 0.0)
    smooth_window = max(3, min(15, int(round((ramp_ms / frame_ms) * 1.5)))) if frame_ms > 0 else 3
    obs_delta = _normalize_signal(_smooth_signal(obs_delta, smooth_window))
    exp_delta = _normalize_signal(_smooth_signal(exp_delta, smooth_window))
    corr, lag = _best_lag_corr(obs_delta, exp_delta, _AOCV_MAX_LAG_FRAMES, signed=True)
    p_val = _shuffle_p_value(
        obs_delta, exp_delta, _AOCV_MAX_LAG_FRAMES, _AOCV_P_SHUFFLES, signed=True
    )
    corr_pass = bool(p_val < 0.01 and corr > 0.0)
    observed = "true" if corr_pass else "inconclusive"
    result = {
        "observed": observed,
        "method": "correlation_best_effort",
        "lag_frames": lag,
        "signal_mode": "delta_abs",
        "detrend_window": detrend_window,
        "ramp_ms": ramp_ms,
        "smooth_window": smooth_window,
    }
    diag = {
        "correlation": corr,
        "p_value": p_val,
    }
    return result, diag

def _verify_focus_coarse(
    signal: np.ndarray,
    frame_ms: float,
    events: List[Dict[str, Any]],
    ramp_ms: int,
    rate_hz: Optional[float],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if signal.size < 4:
        return (
            {"observed": "inconclusive", "reason": "insufficient signal"},
            {"frames": int(signal.size)}
        )
    detrend_window = _detrend_window(rate_hz, frame_ms)
    obs = _normalize_signal(_detrend_signal(signal, detrend_window))
    smooth_window = max(3, min(11, int(round(max(ramp_ms, 1) / frame_ms)))) if frame_ms > 0 else 3
    window_frames = _event_window_frames(ramp_ms, frame_ms)
    detected_ms, detect_diag = _detect_blind_events(
        obs,
        frame_ms,
        min_separation_s=_AOCV_EVENT_MIN_SEPARATION_S,
        smooth_window=smooth_window,
        z_threshold=_AOCV_EVENT_Z_THRESHOLD,
        window_frames=window_frames
    )
    expected_ms = [int(e["t_ms"]) for e in events]
    match_frames = _match_window_frames(1000.0 / frame_ms) if frame_ms > 0 else _AOCV_FOCUS_MATCH_MAX_FRAMES
    aligned_offset, matched, extra = _best_alignment(
        expected_ms,
        detected_ms,
        frame_ms=frame_ms,
        match_window_frames=match_frames,
        max_offset_frames=_AOCV_ALIGN_MAX_FRAMES
    )
    observed, required, extra_limit = _observed_decision(
        expected_events=len(expected_ms),
        matched_events=matched,
        extra_events=extra,
        duration_ms=signal.size * frame_ms
    )
    result = {
        "observed": observed,
        "expected_events": len(expected_ms),
        "matched_events": matched,
        "extra_events": extra,
        "detected_events": len(detected_ms),
        "required_matches": required,
        "extra_event_limit": extra_limit,
        "match_window_frames": match_frames,
        "detect_window_frames": window_frames,
        "aligned_offset_frames": aligned_offset,
        "aligned_offset_ms": int(round(aligned_offset * frame_ms)),
        "signal_mode": "sharpness",
        "detrend_window": detrend_window,
        "ramp_ms": ramp_ms,
    }
    diag = {}
    diag.update(detect_diag)
    return result, diag

def _verify_optical_aocv(
    path: str,
    payload_map: Dict[str, Any],
    *,
    analog_csv_path: Optional[str] = None
) -> Tuple[str, str, Dict[str, Any], Dict[str, Any]]:
    trust = payload_map.get("trust") if isinstance(payload_map, dict) else None
    channels_raw = trust.get("aocv_channels") if isinstance(trust, dict) else None
    channels = [str(c).lower() for c in channels_raw] if isinstance(channels_raw, list) else []
    if not channels:
        return ("UNVERIFIED", "aocv channels missing", {}, {"error": "no_aocv_channels"})

    aocv = payload_map.get("aocv") if isinstance(payload_map, dict) else None
    events = aocv.get("events") if isinstance(aocv, dict) else None
    if not isinstance(events, list) or not events:
        return ("UNVERIFIED", "aocv events missing", {}, {"error": "no_aocv_events"})

    try:
        src_w, src_h, src_fps = _ffprobe_stream_info(path)
        sample_fps = min(_AOCV_SAMPLE_FPS, src_fps or _AOCV_SAMPLE_FPS)
        sample_fps = max(1.0, sample_fps)
        scale_w, scale_h = _scaled_dims(src_w, src_h)
        tiles, tile_diag = _select_tiles(path, scale_w, scale_h, sample_fps)
        signal, sig_diag = _sharpness_signal(path, scale_w, scale_h, sample_fps, tiles)
    except Exception as e:
        return ("FAIL", f"optical decode failed: {e}", {}, {"error": str(e)})

    if signal.size < 4:
        return ("UNVERIFIED", "insufficient frames", {}, {"frames": int(signal.size)})

    frame_ms = 1000.0 / sample_fps
    focus_quality = (aocv.get("focus_quality") if isinstance(aocv, dict) else None) or ""
    focus_quality = str(focus_quality).upper()
    ramp_ms = 600
    params = aocv.get("parameters") if isinstance(aocv, dict) else None
    params = params if isinstance(params, dict) else {}
    if isinstance(params.get("ramp_ms"), int):
        ramp_ms = params["ramp_ms"]
    rate_hz = None
    rate_hz_milli = aocv.get("rate_hz_milli") if isinstance(aocv, dict) else None
    if isinstance(rate_hz_milli, (int, float)):
        rate_hz = float(rate_hz_milli) / 1000.0

    verification: Dict[str, Any] = {}
    verification_channels = [c for c in channels if c != "analog"]
    focus_diag = None
    coarse_diag = None
    if "focus_fine" in verification_channels:
        verification["focus_fine"], focus_diag = _verify_focus_fine(signal, frame_ms, events, ramp_ms, rate_hz)
    if "focus_coarse" in verification_channels:
        verification["focus_coarse"], coarse_diag = _verify_focus_coarse(signal, frame_ms, events, ramp_ms, rate_hz)
    analog_diag = None
    if "analog" in verification_channels:
        analog = aocv.get("analog") if isinstance(aocv, dict) else None
        if isinstance(analog, dict):
            verification["analog"], analog_diag = _verify_analog(
                path,
                analog,
                params,
                scale_w,
                scale_h,
                sample_fps,
                frame_ms,
                analog_csv_path=analog_csv_path
            )
        else:
            verification["analog"] = {"observed": "inconclusive", "reason": "analog missing"}
    if "depth" in channels:
        verification["depth"] = {"observed": "inconclusive", "reason": "depth frames missing"}

    observed_values = [v.get("observed") for v in verification.values() if isinstance(v, dict)]
    if any(v == "true" for v in observed_values):
        status = "PASS"
        reason = "one or more channels observed"
    elif any(v == "false" for v in observed_values):
        status = "UNVERIFIED"
        reason = "no channels observed"
    else:
        status = "UNVERIFIED"
        reason = "all channels inconclusive"

    diag = {
        "sample_fps": sample_fps,
        "scale_width": scale_w,
        "scale_height": scale_h,
        "frame_ms": frame_ms,
    }
    diag.update(tile_diag)
    diag.update(sig_diag)
    if focus_diag is not None:
        diag["focus_fine_diagnostics"] = focus_diag
    if coarse_diag is not None:
        diag["focus_coarse_diagnostics"] = coarse_diag
    if analog_diag is not None:
        diag["analog_diagnostics"] = analog_diag
    if focus_quality:
        diag["focus_quality"] = focus_quality
    if rate_hz_milli is not None:
        diag["rate_hz_milli"] = rate_hz_milli
    return (status, reason, verification, diag)


def verify_path(
    path: str,
    *,
    details: bool = False,
    public_key_pem: Optional[bytes] = None,
    require_aocv: bool = True,
    analog_csv_path: Optional[str] = None
) -> VerifyResult:
    """
    Full verifier:
      - extract manifest (COSE or CBOR),
      - if COSE: verify using supplied public key OR attestation leaf key (video: attestation_chain; photo: trust.cert_chain_der),
      - enforce ES256 and key binding (signer_key_id + kid prefix) [signer_key_id optional for photos],
      - recompute chunk chain (frames/bytes) from the actual file for videos,
      - recompute Himg for photos (only if byteset.himg is present),
      - map tier (SILVER when attested TEE + valid COSE; for photos use trust.tier if present),
      - watermark checks are deprecated (watermark_status is fixed to 'UNVERIFIED').
    """
    file_hash = sha256_file(path)
    man = _extract_manifest_blob(path)

    # ---- Decode payload -> dict
    if man["format"] == "cose_sign1":
        cose = man["cose"]
        payload_map = cbor2.loads(man["payload"])
    else:
        cose = None
        payload_map = cbor2.loads(man["payload"])

    # Type detection (best-effort; schema is preferred when present)
    schema_name = None
    if isinstance(payload_map, dict):
        schema_name = (payload_map.get("schema") or {}).get("name")
    is_photo = bool(schema_name == "capture.photo")
    is_video = bool(schema_name == "capture.video" or (not is_photo and path.lower().endswith(".mp4")))

    # ---- Signature status
    sig_status = "UNVERIFIED"
    sig_reason = None
    if man["format"] == "cose_sign1":
        # Always enforce ES256 first
        alg, kid, _ = _cose_headers(cose)
        ok_alg, alg_reason = _ensure_es256(alg)
        if not ok_alg:
            sig_status, sig_reason = ("UNVERIFIED", alg_reason)
        else:
            if public_key_pem:
                # Verify signature; also enforce key binding if manifest provides signer_key_id
                try:
                    ok = verify_cose_sign1(cose, public_key_pem)
                    if not ok:
                        sig_status, sig_reason = ("FAIL", "COSE verify failed with provided public key")
                    else:
                        spki_der = _spki_der_from_pem_or_der(public_key_pem)
                        if spki_der and isinstance(payload_map, dict) and payload_map.get("signer_key_id") is not None:
                            spki_sha256 = hashlib.sha256(spki_der).digest()
                            signer_key_id = payload_map.get("signer_key_id")
                            if isinstance(signer_key_id, str):
                                try:
                                    signer_key_id = binascii.unhexlify(signer_key_id.strip())
                                except Exception:
                                    signer_key_id = signer_key_id.encode("utf-8")
                            if not isinstance(signer_key_id, (bytes, bytearray)):
                                sig_status, sig_reason = ("UNVERIFIED", "Malformed signer_key_id")
                            elif bytes(signer_key_id) != spki_sha256:
                                sig_status, sig_reason = ("FAIL", "signer_key_id != SHA-256(SPKI of provided key)")
                            else:
                                # Optional: kid prefix check if kid present
                                if kid is not None and bytes(kid) != spki_sha256[: len(kid)]:
                                    sig_status, sig_reason = ("FAIL", "COSE kid is not a prefix of SHA-256(SPKI)")
                                else:
                                    sig_status, sig_reason = ("PASS", "COSE verified with provided key; key binding OK")
                        else:
                            sig_status, sig_reason = ("PASS", "COSE verified with provided public key")
                except Exception as e:
                    sig_status, sig_reason = ("FAIL", f"COSE verify with provided key failed: {e}")
            else:
                # Attestation path does both signature + key binding checks (with photo relaxation)
                sig_status, sig_reason = _verify_cose_with_attestation(cose, payload_map)

    # ---- Pin check (whole-file SHA-256 if present)
    pin_ok: Optional[bool] = True
    pin_expected: Optional[str] = None
    photo_content_pin: Optional[str] = None

    if isinstance(payload_map, dict):
        pin_expected = ((payload_map.get("media") or {}).get("sha256")
                        or payload_map.get("content_hash"))
        photo_content_pin = (payload_map.get("integrity") or {}).get("content_sha256")

        if pin_expected:
            pin_ok = (str(pin_expected).lower() == file_hash.lower())
        else:
            pin_ok = None  # unknown/irrelevant (e.g., photos)

    # ---- Chain / Integrity recompute
    chain_status = "UNVERIFIED"
    diag: Dict[str, Any] = {}

    def _norm_hex(x) -> Optional[str]:
        if x is None: return None
        if isinstance(x, bytes): x = x.hex()
        s = str(x).strip().lower()
        if s.startswith("0x"): s = s[2:]
        return s

    expected_root = None
    expected_chunks = None
    if isinstance(payload_map, dict):
        expected_root = (payload_map.get("merkle_root")
                         or (payload_map.get("integrity") or {}).get("merkle_root"))
        cj = payload_map.get("chunks_json") or payload_map.get("chunks")
        if isinstance(cj, str):
            try:
                expected_chunks = json.loads(cj)
            except Exception:
                expected_chunks = None
        elif isinstance(cj, list):
            expected_chunks = cj

    chunk_mode = (payload_map.get("chunk_mode") or "bytes").lower() if isinstance(payload_map, dict) else "bytes"
    algo = (payload_map.get("chunk_alg") or "sha-256").lower() if isinstance(payload_map, dict) else "sha-256"

    # Video path (chunks/Merkle)
    if expected_root and algo == "sha-256":
        try:
            if chunk_mode == "frames":
                frames_per_chunk = int(payload_map.get("chunk_frames") or 5)
                recomputed_chunks = recompute_chunk_hashes_frames_path(path, frames_per_chunk)
            elif chunk_mode == "bytes":
                chunk_size = int(payload_map.get("chunk_size") or (1 * 1024 * 1024))
                recomputed_chunks = recompute_chunk_hashes_bytes_path(path, chunk_size)
            else:
                recomputed_chunks = []

            recomputed_root = _merkle_root_hex(recomputed_chunks) if recomputed_chunks else None
            exp = _norm_hex(expected_root)
            got = _norm_hex(recomputed_root)
            same_root = (exp is not None and got is not None and got == exp)

            first_mismatch = None
            if expected_chunks and recomputed_chunks and len(expected_chunks) == len(recomputed_chunks):
                for idx, (e, g) in enumerate(zip(expected_chunks, recomputed_chunks)):
                    if _norm_hex(e) != _norm_hex(g):
                        first_mismatch = {"index": idx, "expected": e, "got": g}
                        break

            chain_status = "PASS" if same_root else "FAIL"
            if got == exp:  # sanity guard
                chain_status = "PASS"

            diag.update({
                "mode": chunk_mode,
                "chunks": len(recomputed_chunks),
                "expected_merkle_root": exp,
                "recomputed_merkle_root": got,
                "first_mismatch": first_mismatch,
            })
        except Exception as e:
            chain_status = "UNVERIFIED"
            diag["error"] = f"chunk recompute error: {e}"

    # Photo path (Himg) — accept byteset.himg, integrity.himg[_sha256], or media.himg.root
    if is_photo and isinstance(payload_map, dict):
        try:
            content_type = str((payload_map.get("integrity") or {}).get("content_type") or "").lower()
            bset = (payload_map.get("byteset") or {})
            integrity = payload_map.get("integrity") or {}
            media = payload_map.get("media") or {}
            photo_himg = bset.get("himg") or (media.get("himg") or {}).get("root")
            if isinstance(photo_himg, (bytes, bytearray)):
                photo_himg = bytes(photo_himg).hex()
            photo_himg = str(photo_himg).strip().lower() if photo_himg else None

            himg_sha = integrity.get("himg_sha256") or integrity.get("himg")
            if isinstance(himg_sha, (bytes, bytearray)):
                himg_sha = bytes(himg_sha).hex()
            himg_sha = str(himg_sha).strip().lower() if himg_sha else None

            is_ciphertext = (content_type == "ciphertext_v1") or has_atix_ciphertext(path)
            checks = []

            expected_root = photo_himg
            if expected_root is None and is_ciphertext:
                expected_root = himg_sha

            if expected_root:
                want = _norm_hex(expected_root)
                leaf_size = (media.get("himg") or {}).get("leaf_size") or bset.get("leaf_size")
                leaf_size = int(leaf_size) if isinstance(leaf_size, (int, float)) else 4096
                if is_ciphertext:
                    crypto = extract_atix_crypto(path)
                    if crypto:
                        _, _, _, ciphertext = crypto
                        leaves = []
                        h = hashlib.sha256
                        for i in range(0, len(ciphertext), leaf_size):
                            leaves.append(h(ciphertext[i : i + leaf_size]).hexdigest())
                        recomputed_root = _norm_hex(_merkle_root_hex(leaves))
                        checks.append(recomputed_root == want)
                        diag.update({
                            "mode": "photo",
                            "ciphertext": True,
                            "himg_expected": want,
                            "himg_recomputed": recomputed_root,
                            "leaf_size": leaf_size,
                            "leaf_count": len(leaves)
                        })
                    else:
                        chain_status = "UNVERIFIED"
                        diag.update({"mode": "photo", "note": "ciphertext not found for ATIX"})
                else:
                    with open(path, "rb") as f:
                        scan = extract_jpeg_scan(f.read())
                    leaves = []
                    h = hashlib.sha256
                    for i in range(0, len(scan), leaf_size):
                        leaves.append(h(scan[i : i + leaf_size]).hexdigest())
                    recomputed_root = _norm_hex(_merkle_root_hex(leaves))
                    checks.append(recomputed_root == want)
                    diag.update({
                        "mode": "photo",
                        "ciphertext": False,
                        "himg_expected": want,
                        "himg_recomputed": recomputed_root,
                        "leaf_size": leaf_size,
                        "leaf_count": len(leaves)
                    })

            if not is_ciphertext and himg_sha:
                got_scan = hash_jpeg_scan(path)
                checks.append(got_scan.lower() == himg_sha.lower())
                diag.update({
                    "himg_sha_expected": himg_sha.lower(),
                    "himg_sha_recomputed": got_scan.lower()
                })

            if checks:
                chain_status = "PASS" if all(checks) else "FAIL"
            elif "note" not in diag:
                diag.update({"mode": "photo", "note": "no himg hash in manifest"})
        except Exception as e:
            chain_status = "UNVERIFIED"
            diag["error_photo"] = f"himg recompute error: {e}"

    # ---- Watermark: deprecated
    wm_status = "UNVERIFIED"

    # ---- Tier mapping
    tier = "FAILED"
    tier_reason = "No attestation"
    if isinstance(payload_map, dict):
        att = payload_map.get("attestation") or {}
        trust = payload_map.get("trust") or {}

        if att:
            from .attestation import evaluate_tier as eval_tier
            tier, tier_reason = eval_tier({"attestation": att})
        else:
            has_chain = bool(payload_map.get("attestation_chain")
                             or att.get("chain")
                             or trust.get("cert_chain_der"))
            if sig_status == "PASS" and has_chain:
                tier = (trust.get("tier") or "SILVER").upper()
                tier_reason = "COSE verified with attested leaf (TEE); chain present"

    # ---- Final outcome
    hard_pin_fail = (pin_expected is not None and pin_ok is False)
    aocv_status = "UNVERIFIED"
    aocv_reason = None
    aocv_diag: Dict[str, Any] = {}
    aocv_verification: Dict[str, Any] = {}
    aocv_verification_status: Optional[str] = None
    aocv_verification_reason: Optional[str] = None
    aocv_verification_diag: Dict[str, Any] = {}
    if isinstance(payload_map, dict) and (is_video or is_photo):
        expected = "video-micropull" if is_video else ("photo-burst" if is_photo else None)
        aocv_status, aocv_reason, aocv_diag = _validate_aocv(payload_map, expected_mode=expected)
        if aocv_status == "PASS" and is_video:
            (aocv_verification_status,
             aocv_verification_reason,
             aocv_verification,
             aocv_verification_diag) = _verify_optical_aocv(
                 path,
                 payload_map,
                 analog_csv_path=analog_csv_path
            )

    require_aocv_fail = (require_aocv and (is_video or is_photo) and aocv_status != "PASS")

    if sig_status == "FAIL" or hard_pin_fail or chain_status == "FAIL" or require_aocv_fail:
        outcome = VerifyOutcome.FAIL
        if require_aocv_fail:
            reason = f"AOCV required but {aocv_status}: {aocv_reason or ''}".strip()
        else:
            reason = "Signature/pin/chain failed"
    elif tier in ("GOLD", "SILVER"):
        outcome = VerifyOutcome.PASS if (chain_status in ("PASS", "UNVERIFIED")) else VerifyOutcome.UNVERIFIED
        reason = f"Verified structure; tier {tier} ({tier_reason})"
    elif tier == "UNTRUSTED":
        outcome = VerifyOutcome.UNTRUSTED
        reason = "Structure ok but attestation untrusted"
    else:
        outcome = VerifyOutcome.UNVERIFIED
        reason = "Insufficient evidence to verify"

    det: Dict[str, Any] = {}
    if details:
        attestation_diag = {
            "attestation_state": (payload_map.get("attestation_state")
                                  if isinstance(payload_map, dict) else None),
            "attestation_chain_length": len(payload_map.get("attestation_chain") or []) if isinstance(payload_map, dict) else None,
            "attestation_tier_hint": (payload_map.get("attestation") or {}).get("tier_hint") if isinstance(payload_map, dict) else None,
        }
        attestation_diag = {
            "attestation_state": (payload_map.get("attestation_state")
                                  if isinstance(payload_map, dict) else None),
            "attestation_chain_length": len(payload_map.get("attestation_chain") or []) if isinstance(payload_map, dict) else None,
            "attestation_tier_hint": (payload_map.get("attestation") or {}).get("tier_hint") if isinstance(payload_map, dict) else None,
        }

        # Attempt to diagnose attestation chain issues if present
        if isinstance(payload_map, dict):
            chain_bytes = payload_map.get("attestation_chain") or []
            try:
                from .attestation import diagnose_attestation_chain
                attestation_diag["attestation_chain_diagnostic"] = diagnose_attestation_chain(chain_bytes)
            except Exception as e:
                attestation_diag["attestation_chain_diagnostic"] = f"diagnostic_failed: {e}"

        det.update({
            "pin_expected": pin_expected,
            "pin_ok": pin_ok,
            "chunk_diagnostics": diag,
            "sig_reason": sig_reason,
            "tier_reason": tier_reason,
            "attestation_diagnostics": attestation_diag,
            "aocv_status": aocv_status if (is_video or is_photo) else None,
            "aocv_reason": aocv_reason if (is_video or is_photo) else None,
            "aocv_diagnostics": aocv_diag if (is_video or is_photo) else None,
        })
        if is_video and aocv_verification_status is not None:
            det["aocv_verification"] = {
                "version": _AOCV_OPTICAL_VERSION,
                "status": aocv_verification_status,
                "reason": aocv_verification_reason,
                "channels": aocv_verification,
                "diagnostics": aocv_verification_diag,
            }
        if photo_content_pin:
            det["photo_content_sha256"] = photo_content_pin

    return VerifyResult(
        outcome=outcome,
        reason=reason,
        tier=tier,
        file_sha256=file_hash,
        chain_status=chain_status,
        signature_status=sig_status,
        watermark_status=wm_status,  # kept for schema compatibility
        attestation_status="PASS" if tier in ("GOLD", "SILVER") else ("UNVERIFIED" if tier == "UNTRUSTED" else "FAIL"),
        aocv_status=aocv_status if (is_video or is_photo) else "UNVERIFIED",
        manifest=payload_map if details else None,
        details=det,
    )
