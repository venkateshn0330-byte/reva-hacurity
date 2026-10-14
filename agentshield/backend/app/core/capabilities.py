"""
AgentShield Delegated Capability & Permission Model (Research Module 3A)
Enforces mathematical attenuation / no-escalation constraints between parent and child agents.
A delegated capability must strictly attenuate permissions (tools, resources, destinations, expiration).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Capability:
    capability_id: str
    agent_id: str
    tools: Set[str]
    resources: Set[str]
    destinations: Set[str]
    expires_at: str  # ISO 8601 string
    parent_id: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Check if capability is expired."""
        if current_time is None:
            current_time = datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return current_time > exp
        except Exception:
            return True


def verify_delegation(parent: Capability, child: Capability) -> Tuple[bool, str]:
    """
    Verify that child capability does not escalate privileges beyond parent.
    Enforces deterministic lattice subset checks:
    1. Child tools must be a subset of parent tools.
    2. Child resources must be a subset of parent resources.
    3. Child destinations must be a subset of parent destinations.
    4. Child expiration must not exceed parent expiration.
    """
    # 1. Tools attenuation
    if not child.tools.issubset(parent.tools):
        escalated = child.tools - parent.tools
        return False, f"Privilege escalation detected: Child claimed unauthorized tools {sorted(list(escalated))}."

    # 2. Resources attenuation
    if not child.resources.issubset(parent.resources):
        escalated = child.resources - parent.resources
        return False, f"Privilege escalation detected: Child claimed unauthorized resources {sorted(list(escalated))}."

    # 3. Destinations attenuation
    if not child.destinations.issubset(parent.destinations):
        escalated = child.destinations - parent.destinations
        return False, f"Privilege escalation detected: Child claimed unauthorized destinations {sorted(list(escalated))}."

    # 4. Temporal attenuation
    try:
        p_exp = datetime.fromisoformat(parent.expires_at.replace("Z", "+00:00"))
        c_exp = datetime.fromisoformat(child.expires_at.replace("Z", "+00:00"))
        if c_exp > p_exp:
            return False, f"Temporal escalation detected: Child expiration ({child.expires_at}) exceeds parent expiration ({parent.expires_at})."
    except Exception as e:
        return False, f"Invalid expiration format: {e}"

    return True, "Delegation verified: Child permissions strictly attenuated within parent scope."


def evaluate_capability_access(
    capability: Capability,
    tool_name: str,
    resource: Optional[str] = None,
    destination: Optional[str] = None,
) -> Tuple[bool, str]:
    """Check if an action is authorized by the given capability."""
    if capability.is_expired():
        return False, f"Capability '{capability.capability_id}' expired at {capability.expires_at}."

    if tool_name not in capability.tools:
        return False, f"Tool '{tool_name}' is not authorized by capability '{capability.capability_id}'."

    if resource and resource not in capability.resources:
        return False, f"Resource '{resource}' is not authorized by capability '{capability.capability_id}'."

    if destination and destination not in capability.destinations:
        return False, f"Destination '{destination}' is not authorized by capability '{capability.capability_id}'."

    return True, f"Operation authorized by capability '{capability.capability_id}'."
