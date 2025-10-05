# jpeg_parser.py
from typing import Optional
import struct
import hashlib

APP11 = 0xFFEB
APP15 = 0xFFEF
MAGIC_HDR = b"ATVXJPG"  # COSE + iv/tag/ct container (we want the COSE length-prefixed inside)
MAGIC_KEY = b"ATVXKEY"  # CEK envelope (not needed for manifest)
TAG_ATIS = b"ATIS"      # APP15 fallback: COSE
TAG_ATIX = b"ATIX"      # APP15 fallback: CBOR

def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]

def _find_next_marker(data: bytes, start: int) -> int:
    i, n = start, len(data)
    while i < n - 1:
        if data[i] == 0xFF and data[i + 1] != 0x00:
            return i
        i += 1
    return -1

def _extract_atvxjpg_manifest(seg: bytes) -> Optional[bytes]:
    """
    seg starts at the APP payload (no marker/len). Layout after MAGIC_HDR:
      ver(u16), mLen(u32), ivLen(u16), tagLen(u16), ctLen(u32),
      manifest[mLen], iv[ivLen], tag[tagLen], ct[ctLen]
    Return just manifest[mLen] (COSE_Sign1 bytes).
    """
    base = len(MAGIC_HDR)
    need = base + 2 + 4 + 2 + 2 + 4
    if len(seg) < need:
        return None
    # ver = struct.unpack_from(">H", seg, base)[0]  # currently unused
    mLen = struct.unpack_from(">I", seg, base + 2)[0]
    off  = base + 2 + 4 + 2 + 2 + 4
    if off + mLen <= len(seg):
        return seg[off:off + mLen]
    return None

def _extract_app15_payload(seg: bytes, tag: bytes) -> Optional[bytes]:
    """
    APP15 fallback body: | TAG(4) | len(u32, BE) | bytes[len] |
    Be len-tolerant: if len field looks bogus, return the remainder after TAG.
    """
    if not seg.startswith(tag):
        return None
    body = seg[len(tag):]
    if len(body) >= 4:
        L = struct.unpack(">I", body[:4])[0]
        rest = body[4:]
        if 0 <= L <= len(rest):
            return rest[:L]
    return body if body else None

def find_app11_atvx(path: str) -> Optional[bytes]:
    """
    Locate embedded manifest bytes (COSE preferred; falls back to CBOR):
      - APP11 + "ATVXJPG": extract length-prefixed COSE from the container.
      - APP15 + "ATIS": COSE (fallback).
      - APP15 + "ATIX": CBOR (fallback).
    Returns the raw manifest bytes (COSE_Sign1 or CBOR), or None.
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
        return None  # not a JPEG

    i, n = 2, len(data)
    found_app15_candidate: Optional[bytes] = None

    while i + 4 <= n:
        mpos = _find_next_marker(data, i)
        if mpos < 0 or mpos + 4 > n:
            break
        marker = (data[mpos] << 8) | data[mpos + 1]
        i = mpos + 2
        if marker == 0xFFD9:  # EOI
            break
        if marker in (0xFF01, 0xFFD0, 0xFFD1, 0xFFD2, 0xFFD3, 0xFFD4, 0xFFD5, 0xFFD6, 0xFFD7):
            continue  # standalone; no length
        if i + 2 > n:
            break
        seg_len = _u16(data, i)
        if seg_len < 2 or i + seg_len > n:
            break
        payload = data[i + 2 : i + seg_len]  # exclude the 2-byte length itself
        i += seg_len

        if marker == APP11 and payload.startswith(MAGIC_HDR):
            m = _extract_atvxjpg_manifest(payload)
            if m:
                return m
        elif marker == APP15:
            # Save best candidate while we keep scanning; prefer ATIS (COSE) over ATIX.
            if payload.startswith(TAG_ATIS):
                m = _extract_app15_payload(payload, TAG_ATIS)
                if m:
                    return m
            elif payload.startswith(TAG_ATIX) and not found_app15_candidate:
                found_app15_candidate = _extract_app15_payload(payload, TAG_ATIX)

        if marker == 0xFFDA:  # SOS; nothing meaningful comes after for our use
            break

    return found_app15_candidate

# --- ATIX-style Himg hashing: include SOF*/DQT/DHT/DRI, each SOS header+entropy, and EOI; exclude SOI/APP*/COM.
def hash_jpeg_himg(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    n = len(data)
    if n < 4 or data[0] != 0xFF or data[1] != 0xD8:
        raise ValueError("Not a JPEG")

    i = 2
    include = {
        0xFFDB, 0xFFC4, 0xFFDD,  # DQT, DHT, DRI
        0xFFC0, 0xFFC1, 0xFFC2, 0xFFC3, 0xFFC5, 0xFFC6, 0xFFC7,
        0xFFC9, 0xFFCA, 0xFFCB, 0xFFCD, 0xFFCE, 0xFFCF,            # SOF*
    }
    SOS, EOI, COM = 0xFFDA, 0xFFD9, 0xFFFE
    APP0, APP15 = 0xFFE0, 0xFFEF
    h = hashlib.sha256()

    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = (data[i] << 8) | data[i + 1]
        i += 2

        if marker == EOI:
            h.update(b"\xFF\xD9")
            break
        if marker in (0xFF01, 0xFFD0, 0xFFD1, 0xFFD2, 0xFFD3, 0xFFD4, 0xFFD5, 0xFFD6, 0xFFD7):
            continue
        if i + 2 > n:
            raise ValueError("Truncated JPEG length")
        seg_len = _u16(data, i)
        if seg_len < 2 or i + seg_len > n:
            raise ValueError("Corrupt JPEG segment")
        seg_start = i - 2
        seg_end = i + seg_len

        if marker == SOS:
            # include SOS header
            h.update(data[seg_start:seg_end])
            # drain entropy until a non-stuffed, non-RST marker
            j = seg_end
            while j + 1 < n:
                k = data.find(b"\xFF", j)
                if k < 0 or k + 1 >= n:
                    raise ValueError("No EOI after SOS")
                b1 = data[k + 1]
                if b1 == 0x00 or (0xD0 <= b1 <= 0xD7):
                    j = k + 2
                    continue
                h.update(data[seg_end:k])  # include entropy
                i = k  # reprocess marker
                break
            continue

        if not (APP0 <= marker <= APP15 or marker == COM):
            if marker in include:
                h.update(data[seg_start:seg_end])
        i = seg_end

    return h.hexdigest()
