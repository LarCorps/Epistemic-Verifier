from typing import Optional, Dict, Any, Tuple, List, Set
import struct
import io
import os
import json
import hashlib
import binascii
import cbor2

from .result import VerifyOutcome, VerifyResult
from .hashing import sha256_file
from .jpeg_parser import find_app11_atvx, hash_jpeg_himg
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

def verify_path(path: str, *, details: bool = False, public_key_pem: Optional[bytes] = None) -> VerifyResult:
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

    # Photo path (Himg only if byteset.himg is present)
    is_photo = isinstance(payload_map, dict) and (payload_map.get("schema") or {}).get("name") == "capture.photo"
    if is_photo:
        try:
            himg = hash_jpeg_himg(path)
            bset = (payload_map.get("byteset") or {})
            photo_himg = bset.get("himg") or (payload_map.get("integrity") or {}).get("himg")
            if isinstance(photo_himg, (bytes, bytearray)):
                photo_himg = bytes(photo_himg).hex()
            if photo_himg:
                want = str(photo_himg).strip().lower()
                chain_status = "PASS" if himg.lower() == want else "FAIL"
                diag.update({"mode": "photo", "himg_recomputed": himg, "himg_expected": want})
            else:
                # App emits content_sha256 for encrypted-original; CLI cannot recompute it.
                diag.update({"mode": "photo", "himg_recomputed": himg, "note": "no byteset.himg in manifest"})
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
    if sig_status == "FAIL" or hard_pin_fail or chain_status == "FAIL":
        outcome = VerifyOutcome.FAIL
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
        det.update({
            "pin_expected": pin_expected,
            "pin_ok": pin_ok,
            "chunk_diagnostics": diag,
            "sig_reason": sig_reason,
            "tier_reason": tier_reason,
        })
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
        manifest=payload_map if details else None,
        details=det,
    )
