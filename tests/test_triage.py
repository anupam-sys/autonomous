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


def test_run_triage_token_budget_packing(cfg, db):
    """Token-centered batching: requests are filled to a token budget, not an item count."""
    from src.models import Target, Finding, TargetKind, SecretType, TriageStatus
    from src.triage.triage import _format_item, _estimate_tokens, SYSTEM_PROMPT
    from unittest.mock import patch
    import json
    import re

    cfg.llm.enabled = True
    cfg.llm.batch_size = 50  # high item cap so the token budget is the real limiter

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
            secret_hash=f"hash_tok_{i}",
            secret_full=f"sk-full-{i}",
            context="x" * 400,  # uniform sizes -> deterministic packing
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

    # budget that fits exactly 4 findings per request (+ system prompt overhead)
    rows = db.untriaged_findings(0.5, 500)
    est_each = _estimate_tokens(_format_item(rows[0]))
    overhead = _estimate_tokens(SYSTEM_PROMPT) + 16
    cfg.llm.request_token_budget = overhead + est_each * 4 + 1

    batch_sizes = []
    with patch("src.triage.triage._client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client_factory.return_value = mock_client

        def mock_create(*args, **kwargs):
            messages = kwargs.get("messages", [])
            user_msg = messages[1]["content"] if len(messages) > 1 else ""
            ids = [int(m) for m in re.findall(r"FINDING #(\d+)", user_msg)]
            batch_sizes.append(len(ids))
            verdicts = [{"id": fid, "verdict": "true_positive", "confidence": 0.9, "reason": "verified"} for fid in ids]
            mock_resp = MagicMock()
            mock_resp.choices = [MagicMock(message=MagicMock(content=json.dumps({"verdicts": verdicts})))]
            return mock_resp

        mock_client.chat.completions.create.side_effect = mock_create

        stats = run_triage(ctx)

        # 12 findings, 4 per token-budgeted request -> exactly 3 requests of 4
        assert stats["requests"] == 3
        assert batch_sizes == [4, 4, 4]
        assert stats["triaged"] == 12
