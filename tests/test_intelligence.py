"""Tests for target intelligence engine and selective acquisition."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from src.acquire.package_fetcher import is_scannable_member
from src.config import Config
from src.discovery.intelligence import evaluate_target
from src.models import Target, TargetKind


def test_bot_repo_rejected():
    target = Target(
        kind=TargetKind.REPO,
        source="github_firehose",
        locator="https://github.com/PursuerOtokagePurge/repo-dwtuo59t.git",
        name="PursuerOtokagePurge/repo-dwtuo59t",
    )
    ev = evaluate_target(target)
    assert not ev.keep
    assert "bot-generated or spam pattern" in ev.reason


def test_noise_repos_rejected():
    noise_names = [
        "john/my-leetcode-solutions",
        "alice/awesome-python-tools",
        "bob/cs101-homework-3",
        "user/4k-anime-wallpapers",
        "user/dogdrip-archive",
    ]
    for name in noise_names:
        target = Target(
            kind=TargetKind.REPO,
            source="github_recent",
            locator=f"https://github.com/{name}.git",
            name=name,
        )
        ev = evaluate_target(target)
        assert not ev.keep, f"expected {name} to be rejected"
        assert ev.category == "noise"


def test_apk_bloatware_rejected():
    bloatware = [
        "com.google.android.setupwizard",
        "xiaomi-compass-17-1-4-1-release",
        "youtube-kids-11-36-544-release",
        "diagnosticstool-3-1-0-release",
    ]
    for app in bloatware:
        target = Target(
            kind=TargetKind.APK,
            source="apkmirror",
            locator=f"https://apkmirror.com/apk/{app}/",
            name=app,
        )
        ev = evaluate_target(target)
        assert not ev.keep
        assert ev.category == "bloatware"


def test_dummy_packages_rejected():
    dummies = ["pypi:test-my-lib", "pypi:dummy_package", "pypi:my-first-pkg", "pypi:asdf-test"]
    for pkg in dummies:
        target = Target(
            kind=TargetKind.PACKAGE,
            source="pypi",
            locator="https://pypi.org/tarball.tar.gz",
            name=pkg,
        )
        ev = evaluate_target(target)
        assert not ev.keep
        assert ev.category == "dummy_package"


def test_high_value_targets_prioritized():
    high_value = [
        ("auth-service-microservice", {"auth", "backend_api"}),
        ("discord-bot-crypto-trader", {"integration_bot", "mobile_fintech"}),
        ("pulumi-aws-infra-deployer", {"cloud_infra"}),
        ("stripe-payment-gateway-client", {"integration_bot", "backend_api"}),
        ("oauth-jwt-login-server", {"auth", "backend_api"}),
    ]
    for name, expected_cats in high_value:
        target = Target(
            kind=TargetKind.REPO,
            source="github_recent",
            locator=f"https://github.com/org/{name}.git",
            name=f"org/{name}",
        )
        ev = evaluate_target(target)
        assert ev.keep
        assert ev.score >= 0.5
        assert ev.category in expected_cats


def test_dork_sources_always_kept():
    target = Target(
        kind=TargetKind.REPO,
        source="github_dork",
        locator="https://github.com/random/anything.git",
        name="random/anything",
    )
    ev = evaluate_target(target)
    assert ev.keep
    assert ev.score == 1.0


def test_profile_readme_rejected():
    target = Target(
        kind=TargetKind.REPO,
        source="github_firehose",
        locator="https://github.com/alice/alice.git",
        name="alice/alice",
    )
    ev = evaluate_target(target)
    assert not ev.keep
    assert ev.category == "profile_readme"


def test_generic_unclassified_rejected():
    target = Target(
        kind=TargetKind.REPO,
        source="github_firehose",
        locator="https://github.com/someuser/my-vacation-pics.git",
        name="someuser/my-vacation-pics",
    )
    ev = evaluate_target(target)
    assert not ev.keep
    assert "no security or backend" in ev.reason


def test_is_scannable_member():
    # Scannable code/config files
    assert is_scannable_member("app/main.py", 1024, max_file_kb=2048)
    assert is_scannable_member("config/settings.json", 512, max_file_kb=2048)
    assert is_scannable_member(".env.production", 256, max_file_kb=2048)
    assert is_scannable_member("src/auth/jwt.ts", 4096, max_file_kb=2048)

    # Binaries and media should be rejected
    assert not is_scannable_member("assets/logo.png", 2048, max_file_kb=2048)
    assert not is_scannable_member("compiled/libnative.so", 10000, max_file_kb=2048)
    assert not is_scannable_member("media/sample.mp4", 50000, max_file_kb=2048)
    assert not is_scannable_member("pkg/binary.whl", 20000, max_file_kb=2048)
    assert not is_scannable_member("docs/manual.pdf", 3000, max_file_kb=2048)
    assert not is_scannable_member("bundle.min.js.map", 10000, max_file_kb=2048)

    # Noise directories should be rejected
    assert not is_scannable_member("node_modules/express/index.js", 500, max_file_kb=2048)
    assert not is_scannable_member("docs/tutorial.md", 500, max_file_kb=2048)
    assert not is_scannable_member("site-packages/urllib3/pool.py", 500, max_file_kb=2048)

    # Overly large files should be rejected
    assert not is_scannable_member("big_data.txt", 3_000_000, max_file_kb=2048)
