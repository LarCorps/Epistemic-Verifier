
from typing import Any, Dict
import cbor2
import json

def load_manifest_from_bytes(b: bytes) -> Dict[str, Any]:
    return cbor2.loads(b)

def pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
