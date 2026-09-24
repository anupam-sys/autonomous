"""LLM verdict parsing robustness."""
from __future__ import annotations

from src.models import TriageStatus
from src.triage.triage import parse_verdict


def test_plain_json():
    v = parse_verdict('{"verdict": "true_positive", "confidence": 0.9, "reason": "real"}')
    assert v.status is TriageStatus.TRUE_POSITIVE
    assert v.confidence == 0.9


def test_fenced_json():
    v = parse_verdict('```json\n{"verdict": "false_positive", "confidence": 0.7, "reason": "fixture"}\n```')
    assert v.status is TriageStatus.FALSE_POSITIVE


def test_prose_around_json():
    v = parse_verdict('Sure! {"verdict": "placeholder", "confidence": 0.2, "reason": "docs"} done.')
    assert v.status is TriageStatus.PLACEHOLDER


def test_severity_adjustment():
    v = parse_verdict('{"verdict": "true_positive", "confidence": 0.9, "severity_adjustment": "critical", "reason": "x"}')
    assert v.severity == "critical"


def test_garbage():
    assert parse_verdict("no json") is None
    assert parse_verdict('{"verdict": "nonsense"}') is None
    assert parse_verdict("{not json}") is None
