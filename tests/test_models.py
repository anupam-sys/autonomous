"""Model helpers: redaction, hashing, context masking, dedup keys."""
from __future__ import annotations

from src.models import Target, TargetKind, mask_context, redact, sha256_str


def test_redact():
    assert redact("AKIAI44QH8DHB7XMPL1F") == "AKIA********PL1F"
    assert redact("short") == "*****"


def test_mask_context():
    ctx = "key = AKIAI44QH8DHB7XMPL1F in code"
    masked = mask_context(ctx, "AKIAI44QH8DHB7XMPL1F")
    assert "AKIAI44QH8DHB7XMPL1F" not in masked
    assert "AKIA********PL1F" in masked


def test_target_dedup_key_stable():
    a = Target(kind=TargetKind.REPO, source="x", locator="u", name="n", version="1")
    b = Target(kind=TargetKind.REPO, source="x", locator="u", name="n", version="1")
    c = Target(kind=TargetKind.REPO, source="x", locator="u", name="n", version="2")
    assert a.dedup_key == b.dedup_key
    assert a.dedup_key != c.dedup_key


def test_sha256_str():
    assert sha256_str("x") == sha256_str("x")
    assert sha256_str("x") != sha256_str("y")
