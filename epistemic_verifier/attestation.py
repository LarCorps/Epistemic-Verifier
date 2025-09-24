
from typing import Dict, Any, Tuple

GOLD = "GOLD"
SILVER = "SILVER"
UNTRUSTED = "UNTRUSTED"
FAILED = "FAILED"

def evaluate_tier(manifest: Dict[str, Any]) -> Tuple[str, str]:
    att = manifest.get('attestation') or {}
    strongbox = bool(att.get('strongbox'))
    tee = bool(att.get('tee'))
    verified = bool(att.get('verified_chain'))
    if strongbox and verified:
        return GOLD, "Hardware: StrongBox; attestation verified"
    if tee and verified:
        return SILVER, "Hardware: TEE; attestation verified"
    if att:
        return UNTRUSTED, "Attestation provided but not verifiable"
    return FAILED, "No attestation"
