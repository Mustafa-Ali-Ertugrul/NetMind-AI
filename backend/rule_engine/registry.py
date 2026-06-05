"""Rule registry — stores and serves registered detection rules."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base_rule import BaseDetectionRule


class RuleRegistry:
    """Registry of detection rules.

    Supports register / get / get_all / clear.
    Not a singleton — create one per analysis session.
    """

    def __init__(self) -> None:
        self._rules: dict[str, BaseDetectionRule] = {}

    def register(self, rule: "BaseDetectionRule") -> None:
        """Register a rule instance. Overwrites if same rule_id exists."""
        if not rule.rule_id:
            raise ValueError(f"Rule {rule.__class__.__name__} has empty rule_id")
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> "BaseDetectionRule | None":
        """Look up a rule by rule_id."""
        return self._rules.get(rule_id)

    def get_all(self) -> list["BaseDetectionRule"]:
        """Return all registered rules (insertion order)."""
        return list(self._rules.values())

    def clear(self) -> None:
        """Remove all registered rules."""
        self._rules.clear()

    def __len__(self) -> int:
        return len(self._rules)
