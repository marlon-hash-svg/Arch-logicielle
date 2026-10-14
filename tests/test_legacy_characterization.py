"""J1-A2 — tests de caractérisation : figent le comportement du script hérité avant refactoring.

On ne juge pas le code, on photographie ce qu'il fait : 5 échecs depuis la même IP -> une alerte.
Aucune vraie base ni vrai SMTP : la base est en mémoire, l'alerte est espionnée.
"""

from __future__ import annotations

import importlib
import sqlite3
from pathlib import Path
from types import ModuleType

import pytest

LINE = "Oct 14 09:00:00 host sshd[42]: Failed password for root from {ip} port 22 ssh2\n"


@pytest.fixture
def legacy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    # Le module ouvre incidents.db à l'import : on l'isole dans un dossier temporaire.
    monkeypatch.chdir(tmp_path)
    module = importlib.import_module("legacy.log_watcher")
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE incidents (ip TEXT, user TEXT)")
    monkeypatch.setattr(module, "DB", db)
    return module


def _run(
    legacy: ModuleType, tmp_path: Path, ips: list[str]
) -> tuple[list[str], list[tuple[str, str]]]:
    log = tmp_path / "auth.log"
    log.write_text("".join(LINE.format(ip=ip) for ip in ips), encoding="utf-8")
    alerts: list[str] = []
    watcher = legacy.LogWatcher(str(log))
    watcher.alert = alerts.append  # espion : aucun e-mail réel
    watcher.run()
    return alerts, legacy.DB.execute("SELECT ip, user FROM incidents").fetchall()


def test_five_failures_from_same_ip_raise_one_alert(legacy: ModuleType, tmp_path: Path) -> None:
    alerts, incidents = _run(legacy, tmp_path, ["10.0.0.66"] * 6)
    assert alerts == ["10.0.0.66 port 22 ssh2"]  # la regex gourmande avale la fin de ligne
    assert incidents == [("10.0.0.66 port 22 ssh2", "root")]


def test_failures_below_threshold_or_spread_raise_no_alert(
    legacy: ModuleType, tmp_path: Path
) -> None:
    ips = ["10.0.0.66"] * 4 + [f"10.0.0.{n}" for n in range(1, 5)]
    alerts, incidents = _run(legacy, tmp_path, ips)
    assert alerts == []
    assert incidents == []
