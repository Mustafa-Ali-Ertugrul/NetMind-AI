"""Tests for RuleRegistry."""

from backend.rule_engine import RuleEngine
from backend.rule_engine.registry import RuleRegistry
from backend.rule_engine.rules import PortScanRule, DNSTunnelingRule


class TestRuleRegistry:
    """RuleRegistry behavior."""

    def test_empty_registry(self):
        reg = RuleRegistry()
        assert len(reg) == 0
        assert reg.get_all() == []

    def test_register_and_get(self):
        reg = RuleRegistry()
        rule = PortScanRule()
        reg.register(rule)
        assert len(reg) == 1
        assert reg.get("NET-001") is rule
        assert reg.get("NET-999") is None

    def test_register_overwrites(self):
        reg = RuleRegistry()
        reg.register(PortScanRule())
        replacement = PortScanRule()
        reg.register(replacement)
        assert reg.get("NET-001") is replacement

    def test_get_all_order(self):
        reg = RuleRegistry()
        a = PortScanRule()
        b = DNSTunnelingRule()
        reg.register(a)
        reg.register(b)
        all_rules = reg.get_all()
        assert all_rules == [a, b]

    def test_clear(self):
        reg = RuleRegistry()
        reg.register(PortScanRule())
        reg.clear()
        assert len(reg) == 0
        assert reg.get_all() == []

    def test_register_empty_id_raises(self):
        class BadRule(PortScanRule):
            rule_id = ""

        reg = RuleRegistry()
        import pytest

        with pytest.raises(ValueError, match="empty rule_id"):
            reg.register(BadRule())

    def test_default_engine_registry(self):
        engine = RuleEngine()
        assert len(engine.registry) == 9
        ids = {r.rule_id for r in engine.registry.get_all()}
        assert ids == {
            "NET-001",
            "NET-002",
            "NET-003",
            "NET-004",
            "NET-005",
            "NET-006",
            "NET-007",
            "NET-008",
            "NET-009",
        }
