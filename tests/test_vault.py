"""Encrypted secret storage: roundtrip, at-rest non-plaintext, backfill."""
from __future__ import annotations

from src import crypto_vault
from src.models import Finding, SecretType, Target, TargetKind


def _f(tid, full=None):
    return Finding(target_id=tid, detector="d", service="aws",
                   secret_type=SecretType.API_KEY, file_path="a", line=1,
                   secret_preview="prev", secret_hash="h1", context="c",
                   severity="high", confidence=0.9, secret_full=full)


def test_vault_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_vault, "_fernet", None)
    monkeypatch.setattr(crypto_vault, "_key_path", lambda: tmp_path / "secret.key")
    blob = crypto_vault.encrypt("super-secret-value")
    assert b"super-secret-value" not in blob
    assert crypto_vault.decrypt(blob) == "super-secret-value"
    # key file created with content
    assert (tmp_path / "secret.key").exists()


def test_finding_stored_encrypted_not_plaintext(db):
    tid, _ = db.upsert_target(Target(kind=TargetKind.REPO, source="t",
                                     locator="u", name="n", version="1"))
    assert db.insert_finding(_f(tid, full="AKIAFULLVALUE123456"))
    # raw DB must NOT contain the plaintext
    raw = db._conn.execute(
        "SELECT secret_preview, secret_enc FROM findings WHERE target_id=?", (tid,)
    ).fetchone()
    assert raw["secret_preview"] == "prev"
    assert raw["secret_enc"] is not None
    assert b"AKIAFULLVALUE123456" not in bytes(raw["secret_enc"])
    # decrypted getter returns the real value
    fid = db._conn.execute(
        "SELECT id FROM findings WHERE target_id=?", (tid,)).fetchone()["id"]
    assert db.get_finding_secret(fid) == "AKIAFULLVALUE123456"


def test_duplicate_backfills_secret(db):
    tid, _ = db.upsert_target(Target(kind=TargetKind.REPO, source="t",
                                     locator="u2", name="n2", version="1"))
    assert db.insert_finding(_f(tid, full=None))          # first: no value
    assert not db.insert_finding(_f(tid, full="BACKFILLED-123456"))  # dup w/ value
    fid = db._conn.execute(
        "SELECT id FROM findings WHERE target_id=?", (tid,)).fetchone()["id"]
    assert db.get_finding_secret(fid) == "BACKFILLED-123456"


def test_no_value_returns_none(db):
    tid, _ = db.upsert_target(Target(kind=TargetKind.REPO, source="t",
                                     locator="u3", name="n3", version="1"))
    db.insert_finding(_f(tid, full=None))
    fid = db._conn.execute(
        "SELECT id FROM findings WHERE target_id=?", (tid,)).fetchone()["id"]
    assert db.get_finding_secret(fid) is None
