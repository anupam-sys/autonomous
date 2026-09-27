"""Scanner rules: seeded secrets detected, placeholders suppressed."""
from __future__ import annotations

import pytest

from src.detect.rules_loader import load_rules
from src.detect.scanner import Scanner, is_placeholder
from src.detect.url_filter import is_noise_url

SEED = '''
String aws = "AKIAI44QH8DHB7XMPL1F";
aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYk3R9Zq2LmN"
stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
db = "mongodb://admin:hunter2pass@cluster0.ab1cd.net/prod"
hook = "https://hooks.slack.com/services/T01234ABCD/B01234EFGH/abcdefABCDEF123456789012"
firebase = "https://myapp-12345.firebaseio.com"
token = "glpat-abcdefghijklmnopqrst"
'''


@pytest.fixture()
def scanner(cfg):
    return Scanner(cfg, load_rules("src/detect/rules"))


def test_expected_detections(scanner):
    dets = {f.detector for f in scanner.scan_text(SEED, "x.java", 1)}
    assert {
        "aws-access-key", "aws-secret-key", "stripe-live-key",
        "mongodb-uri", "slack-webhook", "firebase-rtdb", "gitlab-token",
    } <= dets


def test_placeholders_suppressed(scanner):
    findings = scanner.scan_text(
        'aws = "AKIAIOSFODNN7EXAMPLE"\napi_key = "xxxxxxxxxxxxxxxx"\n'
        'api_key = "your_api_key_here"\n', "x.java", 1)
    assert findings == []


def test_localhost_urls_suppressed(scanner):
    findings = scanner.scan_text(
        'base = "http://admin:secret@localhost:3004/api"\n', "x.ts", 1)
    assert findings == []


def test_is_placeholder():
    # Obvious placeholders
    assert is_placeholder("aaaaaaaaaaaaaa")
    assert is_placeholder("your_api_key")
    assert is_placeholder("dummy-secret-token")
    assert is_placeholder("<YOUR_KEY>")
    assert is_placeholder("test")
    assert is_placeholder("changeme")

    # Real keys containing test / demo / fake / xxx as substrings must NOT be dropped!
    assert not is_placeholder("aB3dE5fG7hI9jK1l")
    assert not is_placeholder("AKIAIOSFODNN7xXxTest123")
    assert not is_placeholder("sk_live_51HxFakeKey9234810234")
    assert not is_placeholder("ghp_demoTokenWithRandomBytes92834")
    assert not is_placeholder("glpat-xxxSecretToken991823746")


def test_noise_url():
    assert is_noise_url("http://user:pass@127.0.0.1:8080/api")
    assert is_noise_url("http://schemas.android.com/apk/res/android")
    assert not is_noise_url("https://backend.acme-corp.io/v1/users")
