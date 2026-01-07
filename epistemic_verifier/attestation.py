
from typing import Dict, Any, Tuple, List
import base64
import subprocess
import tempfile
import textwrap
import hashlib

GOLD = "GOLD"
SILVER = "SILVER"
UNTRUSTED = "UNTRUSTED"
FAILED = "FAILED"

def evaluate_tier(manifest: Dict[str, Any]) -> Tuple[str, str]:
    att = manifest.get('attestation') or {}
    # Prefer explicit manifest attestation_state when present (e.g., ANDROID verifier export)
    att_state = manifest.get('attestation_state') or att.get('state')
    if att_state and str(att_state).upper() != "PASS":
        return UNTRUSTED, f"Attestation state={att_state}"

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


def diagnose_attestation_chain(chain: List[bytes]) -> str:
    """
    Best-effort diagnosis of an attestation chain:
      - Checks that each cert parses.
      - Reports issuer/subject and basicConstraints for quick inspection.
      - Attempts a PKIX validation using openssl if available and reports errors.
    Returns a short diagnostic string.
    """
    if not chain:
        return "No attestation chain"
    parsed = []
    for idx, der in enumerate(chain):
        if not isinstance(der, (bytes, bytearray)):
            return f"Chain[{idx}] not bytes"
        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".der") as f:
            f.write(der)
            name = f.name
        try:
            info = subprocess.check_output(
                ["openssl", "x509", "-inform", "DER", "-in", name, "-noout", "-issuer", "-subject", "-serial", "-ext", "basicConstraints"],
                stderr=subprocess.STDOUT,
            ).decode().strip()
        except Exception as e:
            return f"Chain[{idx}] parse failure: {e}"
        parsed.append(f"[{idx}] {info.replace('\\n', ' | ')}")
    # Try full chain validation with openssl if available.
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as ca, \
             tempfile.NamedTemporaryFile("wb", delete=False, suffix=".der") as leaf:
            # root/intermediates as PEM (all but leaf)
            pem_chain = []
            for der in chain[1:]:
                if not isinstance(der, (bytes, bytearray)):
                    continue
                pem = subprocess.check_output(["openssl", "x509", "-inform", "DER", "-in", "/dev/stdin", "-outform", "PEM"], input=der).decode()
                pem_chain.append(pem)
            ca.write("".join(pem_chain))
            ca.flush()
            leaf.write(chain[0]); leaf.flush()
            subprocess.check_output(
                ["openssl", "verify", "-CAfile", ca.name, leaf.name],
                stderr=subprocess.STDOUT,
            )
            chain_status = "Chain validates with provided roots"
    except Exception as e:
        chain_status = f"Chain validation failed: {e}"

    return chain_status + "; " + " || ".join(parsed)
