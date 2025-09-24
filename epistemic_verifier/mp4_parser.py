
from typing import Optional
import struct

def _u32(b: bytes) -> int:
    return struct.unpack('>I', b)[0]

def _u64(b: bytes) -> int:
    return struct.unpack('>Q', b)[0]

def find_uuid_atvx(path: str) -> Optional[bytes]:
    with open(path, 'rb') as f:
        data = f.read()
    i = 0
    n = len(data)
    while i + 8 <= n:
        size = _u32(data[i:i+4])
        typ = data[i+4:i+8]
        header = 8
        if size == 1:
            if i + 16 > n:
                break
            size = _u64(data[i+8:i+16])
            header = 16
        elif size == 0:
            size = n - i
        if size < header or i + size > n:
            break
        payload = data[i+header:i+size]
        if typ == b'uuid' and len(payload) >= 20:
            # skip usertype (16 bytes), then tag
            tag = payload[16:20]
            if tag in (b'ATVX', b'ATVZ'):
                return payload[20:]
        i += size
    return None
