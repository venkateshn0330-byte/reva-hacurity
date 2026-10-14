"""
AgentShield Taint-Aware Information Flow Model (Research Module 3B)
Separates integrity (TRUSTED / UNTRUSTED) from confidentiality (PUBLIC / CONFIDENTIAL).
Propagates explicit labels and enforces information-flow barriers.

Scope & Known Limitation:
AgentShield enforces taint boundaries on tool invocation boundaries and observable source references.
It does NOT inspect internal LLM reasoning states or unobservable hidden context.
"""

from enum import Enum
from typing import Dict, Optional, Tuple


class IntegrityLevel(Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class ConfidentialityLevel(Enum):
    PUBLIC = "PUBLIC"
    CONFIDENTIAL = "CONFIDENTIAL"


# Sample repository documents with explicit taint labels
DOCUMENT_TAINT_MAP = {
    "doc_sample_001": (IntegrityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
    "doc_public_overview": (IntegrityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
    "doc_public_roadmap": (IntegrityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
    "public_quarterly_report.txt": (IntegrityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
    "confidential_financials_2025": (IntegrityLevel.TRUSTED, ConfidentialityLevel.CONFIDENTIAL),
    "confidential_internal_keys": (IntegrityLevel.TRUSTED, ConfidentialityLevel.CONFIDENTIAL),
    "untrusted_web_input_001": (IntegrityLevel.UNTRUSTED, ConfidentialityLevel.PUBLIC),
}


def check_information_flow(
    source_resource: str,
    action: str,
    target_destination: Optional[str] = None,
    is_consequential: bool = False,
) -> Tuple[bool, str, Dict[str, str]]:
    """
    Enforce information-flow policies:
    1. Untrusted source content must not independently authorize a consequential action.
    2. Confidential information must not flow to unauthorized external destinations.
    """
    integrity, confidentiality = DOCUMENT_TAINT_MAP.get(
        source_resource, (IntegrityLevel.UNTRUSTED, ConfidentialityLevel.CONFIDENTIAL)
    )

    labels = {
        "integrity": integrity.value,
        "confidentiality": confidentiality.value,
        "source": source_resource,
    }

    # Policy 1: Integrity violation (Untrusted -> Consequential Tool Action)
    if integrity == IntegrityLevel.UNTRUSTED and is_consequential:
        return (
            False,
            f"Information-flow violation: Source '{source_resource}' has UNTRUSTED integrity and cannot trigger consequential action '{action}'.",
            labels,
        )

    # Policy 2: Confidentiality violation (Confidential -> External Destination)
    if confidentiality == ConfidentialityLevel.CONFIDENTIAL:
        approved_internal = {"internal_backup", "compliance_vault", "approved_data_warehouse"}
        if target_destination not in approved_internal:
            return (
                False,
                f"Information-flow violation: Source '{source_resource}' is CONFIDENTIAL and cannot flow to external or unapproved destination '{target_destination}'.",
                labels,
            )

    return (
        True,
        f"Information-flow permitted: Integrity ({integrity.value}) and Confidentiality ({confidentiality.value}) satisfied.",
        labels,
    )
