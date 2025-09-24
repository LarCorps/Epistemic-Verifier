
import hashlib
from typing import Tuple, List, Dict, Any, BinaryIO

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: str, chunk_size: int = 2**20) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def verify_chunk_chain(f: BinaryIO, chunks: List[Dict[str, Any]]) -> Tuple[bool, List[Dict[str, Any]]]:
    diags = []
    ok = True
    for i, c in enumerate(chunks):
        off = int(c.get('offset', -1))
        size = int(c.get('size', -1))
        target = c.get('sha256')
        if off < 0 or size <= 0 or not target:
            diags.append({'index': i, 'status': 'UNVERIFIED', 'reason': 'missing offset/size/sha256'})
            ok = False
            continue
        f.seek(off)
        data = f.read(size)
        digest = sha256_hex(data)
        status = 'PASS' if digest.lower() == str(target).lower() else 'FAIL'
        if status != 'PASS':
            ok = False
        diags.append({'index': i, 'status': status, 'computed_sha256': digest, 'expected_sha256': target})
    return ok, diags
