"""LLM verdict parsing robustness and batch triage."""
from __future__ import annotations

from unittest.mock import MagicMock
from src.models import TriageStatus
from src.triage.triage import parse_verdict, parse_batch_verdicts, run_triage


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


def test_batch_verdicts_verdicts_array():
    text = """```json
    {
      "verdicts": [
        {"id": 101, "verdict": "true_positive", "confidence": 0.95, "severity_adjustment": "critical", "reason": "live key"},
        {"id": 102, "verdict": "false_positive", "confidence": 0.8, "reason": "test dummy"}
      ]
    }
    ```"""
    res = parse_batch_verdicts(text)
    assert len(res) == 2
    assert res[101].status is TriageStatus.TRUE_POSITIVE
    assert res[101].severity == "critical"
    assert res[101].confidence == 0.95
    assert res[102].status is TriageStatus.FALSE_POSITIVE


def test_batch_verdicts_list_root():
    text = """[
        {"id": 201, "verdict": "placeholder", "confidence": 0.9, "reason": "example in docs"},
        {"id": 202, "verdict": "true_positive", "confidence": 0.85, "reason": "valid token"}
    ]"""
    res = parse_batch_verdicts(text)
    assert len(res) == 2
    assert res[201].status is TriageStatus.PLACEHOLDER
    assert res[202].status is TriageStatus.TRUE_POSITIVE


def test_batch_verdicts_keyed_dict():
    text = """{
        "301": {"verdict": "true_positive", "confidence": 0.9, "reason": "real secret"},
        "302": {"verdict": "false_positive", "confidence": 0.7, "reason": "mock"}
    }"""
    res = parse_batch_verdicts(text)
    assert len(res) == 2
    assert res[301].status is TriageStatus.TRUE_POSITIVE
    assert res[302].status is TriageStatus.FALSE_POSITIVE


def test_run_triage_batches_requests(cfg, db):
    from src.models import Target, Finding, TargetKind, SecretType, TriageStatus
    import json
    cfg.llm.enabled = True
    cfg.llm.batch_size = 5

    # Insert mock findings into db
    target = Target(kind=TargetKind.REPO, source="test", locator="test/repo", name="test/repo")
    target_id, _ = db.upsert_target(target)

    for i in range(12):
        finding = Finding(
            target_id=target_id,
            detector="openai-key",
            service="openai",
            secret_type=SecretType.API_KEY,
            file_path=f"file_{i}.py",
            line=10,
            secret_preview=f"sk-test-{i}",
            secret_hash=f"hash_{i}",
            secret_full=f"sk-full-{i}",
            context="secret context",
            severity="high",
            confidence=0.8,
            triage_status=TriageStatus.PENDING,
        )
        db.insert_finding(finding)

    class DummyContext:
        def __init__(self, cfg, db):
            self.cfg = cfg
            self.db = db

    ctx = DummyContext(cfg, db)

    # Mock LLM client
    from unittest.mock import patch
    with patch("src.triage.triage._client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client_factory.return_value = mock_client

        def mock_create(*args, **kwargs):
            messages = kwargs.get("messages", [])
            user_msg = messages[1]["content"] if len(messages) > 1 else ""
            import re
            ids = [int(m) for m in re.findall(r"FINDING #(\d+)", user_msg)]
            verdicts = [{"id": fid, "verdict": "true_positive", "confidence": 0.9, "reason": "verified"} for fid in ids]
            mock_resp = MagicMock()
            mock_resp.choices = [MagicMock(message=MagicMock(content=json.dumps({"verdicts": verdicts})))]
            return mock_resp

        mock_client.chat.completions.create.side_effect = mock_create

        stats = run_triage(ctx)

        # 12 findings with batch_size 5 -> ceil(12/5) = 3 requests
        assert stats["requests"] == 3
        assert stats["triaged"] == 12
        assert stats["true_positive"] == 12
        assert mock_client.chat.completions.create.call_count == 3
