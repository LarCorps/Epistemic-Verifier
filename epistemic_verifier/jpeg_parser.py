# jpeg_parser.py
from typing import Optional
import struct

APP11 = 0xFFEB
MAGIC_HDR = b"ATVXJPG"  # manifest+iv+tag+ciphertext header
MAGIC_KEY = b"ATVXKEY"  # wrapped CEK (not needed for manifest)

def find_app11_atvx(path: str) -> Optional[bytes]:
    """
    Returns the COSE manifest bytes embedded in the ATVXJPG APP11 header.
    Layout (after magic):
      ver(u16), mLen(u32), ivLen(u16), tagLen(u16), ctLen(u32), manifest[mLen], iv[], tag[]
    """
    with open(path, 'rb') as f:
        data = f.read()

    i = 2  # skip SOI
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = (data[i] << 8) | data[i+1]
        i += 2
        if marker in (0xFFDA, 0xFFD9):  # SOS or EOI
            break
        if i + 2 > n:
            break
        seg_len = (data[i] << 8) | data[i+1]
        i += 2
        if seg_len < 2 or i + seg_len - 2 > n:
            break
        seg = data[i:i+seg_len-2]
        i += seg_len - 2

        if marker != APP11:
            continue

        if seg.startswith(MAGIC_HDR):
            # Offsets after magic
            base = len(MAGIC_HDR)
            if len(seg) < base + 2 + 4 + 2 + 2 + 4:
                continue
            # ver = struct.unpack_from(">H", seg, base)[0]
            mLen = struct.unpack_from(">I", seg, base + 2)[0]
            off = base + 2 + 4 + 2 + 2 + 4
            if off + mLen <= len(seg):
                return seg[off:off + mLen]
        elif seg.startswith(MAGIC_KEY):
            # Not used for manifest extraction
            pass

    return None
