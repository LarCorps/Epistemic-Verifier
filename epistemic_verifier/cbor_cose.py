
from typing import Dict, Any
import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

ALG_ES256 = -7
ALG_PS256 = -37
ALG_EDDSA = -8

def parse_cose_sign1(blob: bytes) -> Dict[str, Any]:
    arr = cbor2.loads(blob)
    if not isinstance(arr, list) or len(arr) != 4:
        raise ValueError("Not a COSE_Sign1 structure")
    protected_bstr, unprotected, payload, signature = arr
    protected = cbor2.loads(protected_bstr) if protected_bstr else {}
    return {
        'protected': protected,
        'unprotected': unprotected or {},
        'payload': payload,
        'signature': signature,
        'raw_protected': protected_bstr or b"",
    }

def _sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload])

def verify_cose_sign1(cose: Dict[str, Any], public_key_pem: bytes) -> bool:
    alg = cose['protected'].get(1)
    tbs = _sig_structure(cose['raw_protected'], cose['payload'])
    sig = cose['signature']
    key = serialization.load_pem_public_key(public_key_pem)
    try:
        if isinstance(key, rsa.RSAPublicKey) and alg == ALG_PS256:
            key.verify(sig, tbs, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        elif isinstance(key, ec.EllipticCurvePublicKey) and alg == ALG_ES256:
            # try DER; if fails and length=64, convert raw r||s to DER
            try:
                key.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                if len(sig) == 64:
                    r = int.from_bytes(sig[:32], 'big')
                    s = int.from_bytes(sig[32:], 'big')
                    der = encode_dss_signature(r, s)
                    key.verify(der, tbs, ec.ECDSA(hashes.SHA256()))
                    return True
                raise
        elif isinstance(key, ed25519.Ed25519PublicKey) and alg == ALG_EDDSA:
            key.verify(sig, tbs)
            return True
    except InvalidSignature:
        return False
    return False
