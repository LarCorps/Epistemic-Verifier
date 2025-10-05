# mp4_parser.py
from typing import Optional
import struct

# UUIDs from AtvxUuids.kt (big-endian bytes as written in boxes)
ATVX = bytes.fromhex("8b83b7c83f2a4a5e9a2d8d9c9c1f42a1")
ATVZ = bytes.fromhex("4f3d5e8e7d3a4e099f0c3a3b6f60d2b7")

def _u32(b: bytes) -> int:
    return struct.unpack('>I', b)[0]

def _u64(b: bytes) -> int:
    return struct.unpack('>Q', b)[0]

def find_uuid_atvx(path: str) -> Optional[bytes]:
    """
    Extracts the COSE payload from uuid(ATVX) inside moov/udta if present,
    otherwise falls back to a top-level uuid(ATVZ) at EOF.
    """
    with open(path, 'rb') as f:
        data = f.read()

    n = len(data)
    i = 0
    found_atvx = None
    found_atvz = None

    while i + 8 <= n:
        size = _u32(data[i:i+4])
        typ = data[i+4:i+8]
        header = 8

        if size == 1:
            if i + 16 > n: break
            size = _u64(data[i+8:i+16]); header = 16
        elif size == 0:
            size = n - i

        if size < header or i + size > n: break

        payload = data[i+header:i+size]

        if typ == b'uuid' and len(payload) >= 16:
            user = payload[:16]
            body = payload[16:]
            if user == ATVX:
                found_atvx = body
            elif user == ATVZ:
                found_atvz = body

        i += size

    # Prefer ATVX (in moov/udta), else ATVZ
    return found_atvx or found_atvz
