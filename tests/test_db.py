"""Database: dedup, queue transitions, bandwidth, kv."""
from __future__ import annotations

from src.models import Artifact, Finding, SecretType, Target, TargetKind


def _target(version="1.0"):
    return Target(kind=TargetKind.APK, source="t", locator="https://x/app.apk",
                  name="com.x", version=version)


def _finding(tid, h="h1"):
    return Finding(target_id=tid, detector="d", service="aws",
                   secret_type=SecretType.API_KEY, file_path="a.java", line=1,
                   secret_preview="p", secret_hash=h, context="c",
                   severity="high", confidence=0.9)


def test_target_dedup_and_versioning(db):
    tid, new = db.upsert_target(_target())
    assert new
    tid2, new = db.upsert_target(_target())
    assert not new and tid2 == tid
    tid3, new = db.upsert_target(_target(version="2.0"))
    assert new and tid3 != tid  # new version -> new target


def test_finding_dedup(db):
    tid, _ = db.upsert_target(_target())
    assert db.insert_finding(_finding(tid))
    assert not db.insert_finding(_finding(tid))
    assert db.insert_finding(_finding(tid, h="h2"))  # different secret


def test_claim_requeue(db):
    db.upsert_target(_target())
    rows = db.claim_targets(5)
    assert len(rows) == 1
    assert db.claim_targets(5) == []
    assert db.requeue_claimed() == 1
    assert len(db.claim_targets(5)) == 1


def test_claim_by_status(db):
    tid, _ = db.upsert_target(_target())
    db.set_target_status(tid, "acquired")
    assert len(db.claim_targets(5, status="acquired")) == 1


def test_artifact_seen(db):
    tid, _ = db.upsert_target(_target())
    db.insert_artifact(Artifact(target_id=tid, path="p", sha256="abc", size_bytes=1))
    assert db.artifact_seen("abc")
    assert not db.artifact_seen("xyz")


def test_bandwidth_and_kv(db):
    db.add_bandwidth(100)
    db.add_bandwidth(50)
    assert db.bandwidth_today() == 150
    assert db.get_kv("k") is None
    db.set_kv("k", "v")
    assert db.get_kv("k") == "v"
    db.set_kv("k", "v2")
    assert db.get_kv("k") == "v2"


def test_suggestions(db):
    assert db.add_suggestion("dork", "q1")
    assert not db.add_suggestion("dork", "q1")
    assert len(db.suggestions(kind="dork", status="pending")) == 1


def test_priority_claim_ordering(db):
    t_low = Target(kind=TargetKind.REPO, source="t", locator="https://x/low.git",
                   name="org/low-priority", priority=0.2)
    t_high = Target(kind=TargetKind.REPO, source="t", locator="https://x/high.git",
                    name="org/high-priority", priority=0.9)
    db.upsert_target(t_low)
    db.upsert_target(t_high)

    claimed = db.claim_targets(1)
    assert len(claimed) == 1
    assert claimed[0]["name"] == "org/high-priority"  # claimed first due to higher priority


def test_prune_and_rescore_targets(db):
    from src.discovery.intelligence import TargetEvaluation

    t_spam = Target(kind=TargetKind.REPO, source="t", locator="https://x/spam.git",
                    name="bot/repo-1234567")
    t_good = Target(kind=TargetKind.REPO, source="t", locator="https://x/good.git",
                    name="org/api-service")
    db.upsert_target(t_spam)
    db.upsert_target(t_good)

    def mock_eval(t):
        if "repo-" in t.name:
            return TargetEvaluation(keep=False, score=0.0, reason="bot spam")
        return TargetEvaluation(keep=True, score=0.85, reason="good target")

    res = db.prune_and_rescore_targets(mock_eval)
    assert res["skipped"] == 1
    assert res["rescored"] == 1

    # Check status of spam target is skipped
    row = db._conn.execute("SELECT status, error FROM targets WHERE name='bot/repo-1234567'").fetchone()
    assert row["status"] == "skipped"
    assert "bot spam" in row["error"]

    # Check good target priority was updated
    row = db._conn.execute("SELECT priority FROM targets WHERE name='org/api-service'").fetchone()
    assert row["priority"] == 0.85
