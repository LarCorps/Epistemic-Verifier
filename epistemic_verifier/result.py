
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, List

class VerifyOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNTRUSTED = "UNTRUSTED"
    UNVERIFIED = "UNVERIFIED"

@dataclass
class VerifyResult:
    outcome: VerifyOutcome
    reason: str
    tier: str
    file_sha256: Optional[str] = None
    chain_status: str = "UNVERIFIED"  # PASS/FAIL/UNVERIFIED
    signature_status: str = "UNVERIFIED"  # PASS/FAIL/UNVERIFIED
    watermark_status: str = "UNVERIFIED"  # PASS/FAIL/UNVERIFIED
    attestation_status: str = "UNVERIFIED"  # PASS/FAIL/UNVERIFIED
    manifest: Optional[Dict[str, Any]] = None
    details: Dict[str, Any] = field(default_factory=dict)
