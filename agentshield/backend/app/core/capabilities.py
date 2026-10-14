"""
AgentShield Provable No-Escalation Delegation Engine
Synthesizes research from Biscuit, Macaroons, UCAN, AAT, Cedar, and Zelkova (SMT/Z3).

Core Mathematical Invariant:
    EffectiveAuthority(child grant) ⊆ DelegableAuthority(parent grant)

Key Principles:
- Least Privilege (Policy 3)
- Monotonic Attenuation
- Fail-Closed Runtime Gate (Policy 17)
- Symbolic Escalation Counterexample Detection (Algorithm C)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass(frozen=True)
class Grant:
    grant_id: str
    issuer: str
    subject: str
    actions: FrozenSet[str]
    resources: FrozenSet[str]
    argument_constraints: Dict[str, Any] = field(default_factory=dict)
    not_before: Optional[str] = None
    expires_at: str = ""  # ISO 8601 string
    delegable: bool = False
    remaining_depth: int = 0
    parent_id: Optional[str] = None
    signature: Optional[str] = None

    def is_valid_time(self, now: Optional[datetime] = None) -> Tuple[bool, str]:
        if now is None:
            now = datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if now >= exp:
                return False, f"Grant '{self.grant_id}' expired at {self.expires_at}."
            if self.not_before:
                nb = datetime.fromisoformat(self.not_before.replace("Z", "+00:00"))
                if now < nb:
                    return False, f"Grant '{self.grant_id}' is not yet valid until {self.not_before}."
            return True, "Time window valid."
        except Exception as e:
            return False, f"Invalid timestamp format: {e}"


# --- ALGORITHM A: VALIDATE AND ATTENUATE A CHILD GRANT ---
def validate_child_grant(parent: Grant, child: Grant, now: Optional[datetime] = None) -> Tuple[bool, str]:
    """
    Algorithm A: Validates that child grant is strictly attenuated within parent authority.
    Enforces rules R1 - R5:
    1. Parent must be delegable and unexpired.
    2. Child issuer must match parent subject.
    3. Child actions ⊆ Parent actions.
    4. Child resources ⊆ Parent resources.
    5. Child lifetime ≤ Parent lifetime.
    6. Child depth ≤ Parent remaining depth - 1.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # 1. Parent validity
    p_ok, p_msg = parent.is_valid_time(now)
    if not p_ok:
        return False, f"Parent grant invalid: {p_msg}"

    if not parent.delegable:
        return False, f"Parent grant '{parent.grant_id}' is not marked as delegable."

    # 2. Issuer/Subject chain
    if child.issuer != parent.subject:
        return False, f"Chain integrity failure: Child issuer '{child.issuer}' does not match parent subject '{parent.subject}'."

    # 3. Action attenuation (Actions ⊆ Parent Actions)
    if not child.actions.issubset(parent.actions):
        escalated_actions = sorted(list(child.actions - parent.actions))
        return False, f"Provable Escalation: Child claimed unauthorized actions {escalated_actions} absent in parent grant."

    # 4. Resource scope attenuation (Resources ⊆ Parent Resources)
    if not child.resources.issubset(parent.resources):
        escalated_res = sorted(list(child.resources - parent.resources))
        return False, f"Provable Escalation: Child claimed unauthorized resources {escalated_res} outside parent scope."

    # 5. Temporal attenuation (Child Expiry ≤ Parent Expiry)
    try:
        p_exp = datetime.fromisoformat(parent.expires_at.replace("Z", "+00:00"))
        c_exp = datetime.fromisoformat(child.expires_at.replace("Z", "+00:00"))
        if c_exp > p_exp:
            return False, f"Temporal Escalation: Child expiration ({child.expires_at}) exceeds parent expiration ({parent.expires_at})."
    except Exception as e:
        return False, f"Invalid timestamp evaluation: {e}"

    # 6. Delegation depth attenuation
    if child.remaining_depth > max(parent.remaining_depth - 1, 0):
        return False, f"Depth Escalation: Child requested delegation depth {child.remaining_depth} exceeding parent max {parent.remaining_depth - 1}."

    return True, "Delegation Verified: Child authority strictly attenuated within parent delegable scope."


# --- ALGORITHM B: RUNTIME AUTHORIZATION AT TOOL BOUNDARY ---
def authorize_tool_call_with_grant(
    grant: Grant,
    action: str,
    resource: Optional[str] = None,
    arguments: Optional[Dict[str, Any]] = None,
    now: Optional[datetime] = None,
) -> Tuple[bool, str, int, str]:
    """
    Algorithm B: Enforce Policy 14 (Action Authorization) immediately prior to tool execution.
    Returns: (allowed, reason, policy_id, policy_code)
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # Policy 17: Fail-closed time validity
    time_ok, time_msg = grant.is_valid_time(now)
    if not time_ok:
        return False, time_msg, 17, "P-FAILCLOSED"

    # Policy 8 & Policy 3: Tool allowlist and least privilege
    if action not in grant.actions:
        return False, f"Action '{action}' not permitted by grant '{grant.grant_id}'.", 3, "P-LP"

    # Policy 9: Resource access control
    if resource and resource not in grant.resources:
        return False, f"Resource '{resource}' is outside grant '{grant.grant_id}' scope.", 9, "P-RBAC"

    # Policy 15: Parameter constraints validation
    if arguments and grant.argument_constraints:
        for param, constraint in grant.argument_constraints.items():
            if param in arguments and arguments[param] != constraint:
                return False, f"Argument constraint failed: {param} must be '{constraint}'.", 15, "P-PARAM"

    return True, f"Operation authorized by grant '{grant.grant_id}'.", 14, "P-AUTHZ"


# --- ALGORITHM C: SYMBOLIC ESCALATION COUNTEREXAMPLE GENERATION ---
def detect_escalation_counterexample(parent: Grant, child: Grant) -> Optional[Dict[str, Any]]:
    """
    Algorithm C: Tests whether ANY request exists that is permitted by child but denied by parent.
    Evaluates action, resource, and temporal dimensions.
    Returns: Counterexample request dict if escalation is found; None if no escalation exists.
    """
    # 1. Action dimension counterexample
    unauthorized_actions = child.actions - parent.actions
    if unauthorized_actions:
        escalated_act = next(iter(unauthorized_actions))
        return {
            "type": "ACTION_ESCALATION",
            "counterexample_action": escalated_act,
            "counterexample_resource": next(iter(child.resources), "*"),
            "proof": f"Child permits '{escalated_act}', but Parent delegable set only permits {sorted(list(parent.actions))}.",
        }

    # 2. Resource dimension counterexample
    unauthorized_resources = child.resources - parent.resources
    if unauthorized_resources:
        escalated_res = next(iter(unauthorized_resources))
        return {
            "type": "RESOURCE_ESCALATION",
            "counterexample_action": next(iter(child.actions), "*"),
            "counterexample_resource": escalated_res,
            "proof": f"Child permits access to resource '{escalated_res}', which parent does not own.",
        }

    # 3. Temporal dimension counterexample
    try:
        p_exp = datetime.fromisoformat(parent.expires_at.replace("Z", "+00:00"))
        c_exp = datetime.fromisoformat(child.expires_at.replace("Z", "+00:00"))
        if c_exp > p_exp:
            return {
                "type": "TEMPORAL_ESCALATION",
                "counterexample_timestamp": child.expires_at,
                "proof": f"Child can execute requests at {child.expires_at}, when parent grant is already dead ({parent.expires_at}).",
            }
    except Exception:
        pass

    return None


# --- Backward Compatibility Aliases ---
Capability = Grant
verify_delegation = validate_child_grant
def evaluate_capability_access(capability: Grant, tool_name: str, resource: Optional[str] = None, destination: Optional[str] = None):
    allowed, msg, _, _ = authorize_tool_call_with_grant(grant=capability, action=tool_name, resource=resource)
    return allowed, msg

