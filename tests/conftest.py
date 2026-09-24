import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import Config
from src.db import Database


@pytest.fixture()
def cfg(tmp_path):
    c = Config.load("config.yaml")
    c.paths.data_dir = str(tmp_path / "data")
    c.paths.db_path = str(tmp_path / "test.db")
    c.paths.report_dir = str(tmp_path / "reports")
    return c


@pytest.fixture()
def db(tmp_path):
    d = Database(tmp_path / "test.db")
    yield d
    d.close()
