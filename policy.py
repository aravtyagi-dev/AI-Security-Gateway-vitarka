"""
Policy Engine for AI Security Gateway.
Enforces category rules, per-role overrides, score thresholds, right-to-left span masking,
and dynamic hot-reloading from policies.yaml.
"""

import os
import yaml
import logging
from typing import Dict, Any, List, Tuple, Optional
from gateway.models import Finding

logger = logging.getLogger("gateway.policy")

SEVERITY_ORDER = {
    "block": 6,
    "require_approval": 5,
    "redact": 4,
    "mask": 3,
    "warn": 2,
    "allow": 1
}


class PolicyEngine:
    """Evaluates security findings against policies and applies span sanitization."""

    def __init__(self, policy_path: str = "policies.yaml"):
        self.policy_path = policy_path
        self.config: Dict[str, Any] = {}
        self.reload()

    def reload(self) -> bool:
        """Hot-reload policy configuration from disk without service restart."""
        try:
            if not os.path.exists(self.policy_path):
                logger.warning(f"Policy file {self.policy_path} not found. Using defaults.")
                self.config = {"categories": {}, "default_action": "allow"}
                return False

            with open(self.policy_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
            logger.info(f"Loaded policy configuration from {self.policy_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to reload policy config: {e}")
            return False

    def evaluate(self, findings: List[Finding], role: str = "intern") -> Tuple[str, List[Tuple[Finding, str, str]]]:
        """
        Evaluate a list of findings against current policies.
        Returns:
            (overall_action, [(finding, action, policy_id), ...])
        """
        if not findings:
            return "allow", []

        categories_cfg = self.config.get("categories", {})
        default_action = self.config.get("default_action", "allow")

        evaluated: List[Tuple[Finding, str, str]] = []
        highest_severity = 0
        overall_action = "allow"

        for f in findings:
            cat_cfg = categories_cfg.get(f.category, {})
            threshold = cat_cfg.get("threshold", 0.0)

            # Skip finding if below score threshold
            if f.score < threshold:
                continue

            # Determine action: check role_overrides first
            action = cat_cfg.get("action", default_action)
            role_overrides = cat_cfg.get("role_overrides", {})
            if role in role_overrides:
                action = role_overrides[role]

            policy_id = f"policy_{f.category}_{role}"
            evaluated.append((f, action, policy_id))

            # Strictest action wins
            sev = SEVERITY_ORDER.get(action, 1)
            if sev > highest_severity:
                highest_severity = sev
                overall_action = action

        return overall_action, evaluated

    def get_tag_for_category(self, category: str) -> str:
        """Get replacement tag for masking from config."""
        cat_cfg = self.config.get("categories", {}).get(category, {})
        tag = cat_cfg.get("tag")
        if tag:
            return tag
        return f"[{category.upper()}_REDACTED]"

    def mask_spans(self, text: str, evaluated_findings: List[Tuple[Finding, str, str]]) -> str:
        """
        Replace sensitive spans right-to-left so indices remain valid.
        Overlapping or duplicate spans are merged or replaced cleanly.
        """
        mask_items = []
        for finding, action, _ in evaluated_findings:
            if action in ("mask", "redact"):
                mask_items.append((finding.start, finding.end, self.get_tag_for_category(finding.category)))

        if not mask_items:
            return text

        # Sort descending by start index (right-to-left replacement)
        # In case of tie, prioritize larger span first
        mask_items.sort(key=lambda x: (x[0], -x[1]), reverse=True)

        # Filter overlapping spans
        non_overlapping = []
        current_left = len(text) + 1

        for start, end, tag in mask_items:
            # Bound within text length
            start = max(0, min(start, len(text)))
            end = max(start, min(end, len(text)))
            if end <= current_left:
                non_overlapping.append((start, end, tag))
                current_left = start

        # Perform right-to-left replacement
        sanitized = list(text)
        for start, end, tag in non_overlapping:
            sanitized[start:end] = list(tag)

        return "".join(sanitized)
