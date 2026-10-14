"""J1-A3 — tests d'abus sur la création d'objets, la configuration et le démarrage.

On joue l'attaquant (configuration piégée, secret recherché, donnée hostile en base) et on
vérifie le refus ET l'absence d'effet de bord.
"""

from __future__ import annotations

import sqlite3

import pytest

from queenbee.adapters.outbound.notifiers import LogNotifier, MemoryNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.bootstrap import build_app
from queenbee.config import ConfigError, SettingsBuilder, settings_from_env
from queenbee.domain.model import Alert, DomainError, Incident, IncidentStatus, Severity
from queenbee.domain.rules import BruteForceRule, build_rule
from queenbee.factories import InMemoryFactory
from tests.conftest import ev

KEY = bytes(range(32))
ENV = {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_DB": ":memory:"}


# --- Factory : seuls les noms enregistrés, seuls des entiers ---------------------------------


@pytest.mark.parametrize("kind", ["BruteForceRule", "__class__", "os.system", "", 42])
def test_abuse_factory_rejects_unregistered_kind(kind: object) -> None:
    with pytest.raises(DomainError):
        build_rule({"kind": kind, "threshold": 5})


@pytest.mark.parametrize("threshold", [True, False, "5", 0, -1, 2.5, None])
def test_abuse_factory_rejects_non_integer_threshold(threshold: object) -> None:
    with pytest.raises(DomainError):
        build_rule({"kind": "brute_force", "threshold": threshold})


def test_abuse_factory_rejects_extra_or_missing_keys() -> None:
    with pytest.raises(DomainError):
        build_rule({"kind": "brute_force", "threshold": 5, "module": "os"})
    with pytest.raises(DomainError):
        build_rule({"kind": "brute_force"})


def test_factory_builds_registered_rule() -> None:
    assert build_rule({"kind": "port_scan", "threshold": 3}).evaluate([]) == []


@pytest.mark.parametrize(
    ("rule", "severity"), [("", Severity.LOW), ("r", 9)], ids=["empty_rule", "unknown_severity"]
)
def test_invalid_alert_cannot_exist(rule: str, severity: Severity) -> None:
    with pytest.raises(DomainError):
        Alert(rule, "10.0.0.1", severity, "x")


# --- Builder : validé à la fin, figé, secret jamais affiché ----------------------------------


def test_secret_absent_from_repr_str_and_builder() -> None:
    builder = SettingsBuilder().hmac_key(KEY)
    settings = builder.build()
    for text in (repr(settings), str(settings), repr(builder)):
        assert KEY.hex() not in text
        assert str(KEY) not in text


def test_abuse_secret_not_leaked_by_invalid_key_error() -> None:
    with pytest.raises(ConfigError) as info:
        settings_from_env({"QUEENBEE_AGENT_KEY": "zz" + KEY.hex()})
    assert KEY.hex() not in str(info.value)
    assert info.value.__cause__ is None


@pytest.mark.parametrize(
    "builder",
    [
        SettingsBuilder(),
        SettingsBuilder().hmac_key(b"court"),
        SettingsBuilder().hmac_key(KEY).db_path(""),
        SettingsBuilder().hmac_key(KEY).bf_threshold(True),
        SettingsBuilder().hmac_key(KEY).bf_threshold("5"),
        SettingsBuilder().hmac_key(KEY).bf_threshold(0),
    ],
    ids=["no_key", "short_key", "empty_db", "bool_threshold", "str_threshold", "zero_threshold"],
)
def test_abuse_builder_refuses_invalid_settings(builder: SettingsBuilder) -> None:
    with pytest.raises(ConfigError):
        builder.build()


@pytest.mark.parametrize("env", [{}, {"QUEENBEE_AGENT_KEY": ""}], ids=["absent", "empty"])
def test_abuse_missing_secret_refuses_to_start(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        settings_from_env(env)


def test_abuse_env_threshold_must_be_integer() -> None:
    with pytest.raises(ConfigError):
        settings_from_env(ENV | {"QUEENBEE_BF_THRESHOLD": "cinq"})


def test_settings_are_frozen_and_read_from_env() -> None:
    settings = settings_from_env(ENV | {"QUEENBEE_BF_THRESHOLD": "3"})
    assert (settings.db_path, settings.bf_threshold) == (":memory:", 3)
    with pytest.raises(AttributeError):
        settings.bf_threshold = 99  # type: ignore[misc]


# --- Dépôts : même contrat, SQL paramétré --------------------------------------------------


@pytest.mark.parametrize(
    "repo",
    [InMemoryIncidentRepository(), SqliteIncidentRepository(sqlite3.connect(":memory:"))],
    ids=["memory", "sqlite"],
)
def test_repositories_share_the_same_contract(
    repo: InMemoryIncidentRepository | SqliteIncidentRepository,
) -> None:
    inc = Incident(Alert("brute_force", "10.0.0.66", Severity.HIGH, "5 échecs"))
    repo.add(inc)
    inc.transition_to(IncidentStatus.TRIAGED)
    inc.transition_to(IncidentStatus.CLOSED)
    repo.save(inc)
    assert repo.get(inc.id) == inc
    assert repo.list_open() == []
    assert repo.get(Incident(inc.alert).id) is None


def test_abuse_sql_payload_is_stored_as_data() -> None:
    conn = sqlite3.connect(":memory:")
    repo = SqliteIncidentRepository(conn)
    payload = "x'); DROP TABLE incident; --"
    inc = Incident(Alert("brute_force", "10.0.0.66", Severity.HIGH, payload))
    repo.add(inc)
    stored = repo.get(inc.id)
    assert stored is not None
    assert stored.alert.detail == payload
    assert conn.execute("SELECT count(*) FROM incident").fetchone() == (1,)


# --- Notificateur prod et composition root -------------------------------------------------


def test_log_notifier_writes_to_alert_journal(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING", logger="queenbee.alerts")
    LogNotifier().notify(Alert("brute_force", "10.0.0.66", Severity.HIGH, "x"))
    assert "rule=brute_force ip=10.0.0.66 severity=HIGH" in caplog.text


def test_build_app_with_memory_family() -> None:
    factory = InMemoryFactory()
    app = build_app(settings_from_env(ENV), factory)
    assert len(app.ingest([ev()] * 5)) == 1
    assert app.ingest([ev()] * 4) == []


def test_build_app_defaults_to_prod_family() -> None:
    app = build_app(settings_from_env(ENV | {"QUEENBEE_BF_THRESHOLD": "2"}))
    [incident] = app.ingest([ev()] * 2)
    assert incident.alert.rule == BruteForceRule.name


def test_no_global_state_between_apps() -> None:
    first, second = InMemoryFactory().notifier(), InMemoryFactory().notifier()
    assert isinstance(first, MemoryNotifier)
    assert first is not second
