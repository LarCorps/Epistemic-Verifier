
from typing import Optional
APP11 = 0xFFEB

def find_app11_atvx(path: str) -> Optional[bytes]:
    with open(path, 'rb') as f:
        data = f.read()
    i = 0
    n = len(data)
    while i + 4 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = (data[i] << 8) | data[i+1]
        i += 2
        if marker == 0xFFD9:  # EOI
            break
        if 0xFFD0 <= marker <= 0xFFD7:  # restart markers
            continue
        if i + 2 > n:
            break
        seg_len = (data[i] << 8) | data[i+1]
        i += 2
        if seg_len < 2 or i + seg_len - 2 > n:
            break
        seg = data[i:i+seg_len-2]
        i += seg_len - 2
        if marker == APP11 and seg.startswith(b'ATVX'):
            return seg[4:]
    return None
