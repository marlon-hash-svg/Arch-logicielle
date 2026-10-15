"""J2-A1 — cinq patterns défensifs, cinq tests d'abus.

Chaque test joue l'attaquant et vérifie deux choses : le refus, ET l'absence d'effet de bord.
Horloge injectée, aucune base réelle, aucun réseau, aucun time.sleep.
"""

from __future__ import annotations

import contextlib
import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from queenbee.adapters.inbound.log_parser import parse_sshd_line
from queenbee.adapters.outbound.notifiers import (
    AuditedNotifier,
    MemoryNotifier,
    RateLimitedNotifier,
)
from queenbee.adapters.outbound.repositories import InMemoryIncidentRepository
from queenbee.adapters.outbound.response import BlockIpCommand, CommandHistory, InMemoryFirewall
from queenbee.application.access import IncidentReadProxy
from queenbee.application.services import AccessDeniedError, DetectionService, IncidentService
from queenbee.domain.model import Alert, DomainError, Incident, IncidentStatus, Principal, Severity
from queenbee.domain.rules import BruteForceRule
from tests.conftest import ev

ANALYST = Principal("alice", frozenset({"analyst"}))
VIEWER = Principal("victor", frozenset({"viewer"}))
NOBODY = Principal("guest", frozenset())
ALERT = Alert("brute_force", "10.0.0.66", Severity.HIGH, "5 échecs")
GOOD = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"


def _repo_with_incident() -> tuple[InMemoryIncidentRepository, Incident]:
    repo, incident = InMemoryIncidentRepository(), Incident(ALERT)
    repo.add(incident)
    return repo, incident


# --- 1. Procuration (Proxy) · C : la lecture des incidents ---------------------------------


def test_abuse_proxy_refuses_without_role_and_counts(caplog: pytest.LogCaptureFixture) -> None:
    repo, incident = _repo_with_incident()
    proxy = IncidentReadProxy(repo, NOBODY)
    caplog.set_level("WARNING", logger="queenbee.audit")
    for call in (proxy.list_open, lambda: proxy.get(incident.id)):
        with pytest.raises(AccessDeniedError):
            call()
    assert proxy.denied == 2
    assert "refus list_open user=guest" in caplog.text


def test_abuse_proxy_viewer_reads_but_cannot_write() -> None:
    repo, incident = _repo_with_incident()
    proxy = IncidentReadProxy(repo, VIEWER)
    assert proxy.list_open() == [incident]
    assert proxy.get(incident.id) == incident
    intruder_copy = Incident(ALERT, incident.id, IncidentStatus.CLOSED)
    for write in (proxy.save, proxy.add):
        with pytest.raises(AccessDeniedError):
            write(intruder_copy)
    assert repo.get(incident.id) is incident  # rien n'a été remplacé
    assert incident.status is IncidentStatus.OPEN
    assert proxy.denied == 2


def test_proxy_lets_analyst_write() -> None:
    repo, incident = _repo_with_incident()
    proxy = IncidentReadProxy(repo, ANALYST)
    other = Incident(ALERT)
    proxy.add(other)
    proxy.save(other)
    assert repo.list_open() == [incident, other]


def test_abuse_service_refuses_viewer_and_audits(caplog: pytest.LogCaptureFixture) -> None:
    repo, incident = _repo_with_incident()
    caplog.set_level("INFO", logger="queenbee.audit")
    with pytest.raises(AccessDeniedError):
        IncidentService(repo).move(VIEWER, incident.id, IncidentStatus.TRIAGED)
    assert incident.status is IncidentStatus.OPEN
    IncidentService(repo).move(ANALYST, incident.id, IncidentStatus.TRIAGED)
    assert "refus move user=victor" in caplog.text
    assert f"move user=alice incident={incident.id} open->triaged" in caplog.text


@pytest.mark.parametrize(
    ("user", "roles"), [("alice", {"admin"}), ("alice; rm", {"analyst"}), ("", set())]
)
def test_abuse_forged_principal_cannot_exist(user: str, roles: set[str]) -> None:
    with pytest.raises(DomainError):
        Principal(user, frozenset(roles))


# --- 2. Décorateur · D, P : le SOC contre l'inondation ------------------------------------


def test_abuse_alert_flood_is_capped_and_every_rejection_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink, now = MemoryNotifier(), [0.0]
    caplog.set_level("INFO", logger="queenbee.audit")
    chain = RateLimitedNotifier(
        AuditedNotifier(sink), max_per_window=3, window_s=60, clock=lambda: now[0]
    )
    for _ in range(1_000):
        chain.notify(ALERT)
    assert len(sink.received) == 3
    assert chain.dropped == 997
    assert caplog.text.count("alerte rule=brute_force") == 3  # l'audit ne voit que ce qui passe
    assert "alertes écartées par le limiteur total=900" in caplog.text
    now[0] = 59.9
    chain.notify(ALERT)
    assert chain.dropped == 998  # la fenêtre n'est pas encore écoulée


@pytest.mark.parametrize(("limit", "window"), [(0, 60), (True, 60), (3, 0), (3, -1)])
def test_abuse_rate_limiter_refuses_disabling_settings(limit: int, window: float) -> None:
    with pytest.raises(ValueError, match="strictement positives"):
        RateLimitedNotifier(MemoryNotifier(), max_per_window=limit, window_s=window)


# --- 3. Adaptateur · I : ligne de journal -> événement ------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        GOOD.replace("10.0.0.66", "10.0.0.66' OR 1=1 --"),
        GOOD.replace("root", "root'); DROP TABLE incident; --"),
        GOOD.replace("10.0.0.66", "999.0.0.1"),
        GOOD.replace("+02:00", ""),  # horodatage sans fuseau
        GOOD.replace("2026-10-14", "2026-13-45"),
        GOOD + "\n" + GOOD,  # deux lignes en une
        "2026-10-14T09:00:00+02:00 sshd: " + "a " * 200,
        "A" * 513,
    ],
)
def test_abuse_trapped_log_line_rejected(line: str) -> None:
    with pytest.raises(DomainError):
        parse_sshd_line(line)


def test_adapter_translates_accepted_login_and_invalid_user() -> None:
    ok = parse_sshd_line(GOOD.replace("Failed", "Accepted"))
    assert ok.action == "login_ok"
    invalid = parse_sshd_line(GOOD.replace("for root", "for invalid user bob"))
    assert invalid.username == "bob"


@given(st.text(max_size=600))
def test_adapter_only_ever_raises_domain_error(line: str) -> None:
    with contextlib.suppress(DomainError):
        parse_sshd_line(line)


# --- 4. Observateur (bonus) · D : un abonné en panne ne bloque pas les autres ---------------


class BrokenNotifier:
    def notify(self, alert: Alert) -> None:
        raise ConnectionError("SMTP injoignable")


def test_abuse_broken_subscriber_does_not_silence_others(
    caplog: pytest.LogCaptureFixture,
) -> None:
    repo, healthy = InMemoryIncidentRepository(), MemoryNotifier()
    service = DetectionService(BruteForceRule(), repo, [BrokenNotifier(), healthy])
    with caplog.at_level(logging.ERROR, logger="queenbee.application.services"):
        [incident] = service.ingest([ev()] * 5)
    assert healthy.received == [incident.alert]
    assert repo.list_open() == [incident]
    assert service.notify_failures == 1
    assert "BrokenNotifier" in caplog.text
    assert "SMTP injoignable" in caplog.text  # la cause est gardée, pas avalée


# --- 5. Commande · I, P : blocage d'IP -----------------------------------------------------


@pytest.mark.parametrize(
    "target", ["10.0.0.1; iptables -F", "0.0.0.0/0", "$(reboot)", "10.0.0.1 ", ""]
)
def test_abuse_trapped_ip_never_reaches_firewall(target: str) -> None:
    firewall, history = InMemoryFirewall(), CommandHistory()
    with pytest.raises(DomainError):
        history.run(BlockIpCommand(firewall, target))
    assert firewall.blocked == set()
    with pytest.raises(DomainError):
        history.undo_last()  # rien n'a été enregistré


def test_command_is_audited_and_canonical(caplog: pytest.LogCaptureFixture) -> None:
    firewall, history = InMemoryFirewall(), CommandHistory()
    caplog.set_level("INFO", logger="queenbee.audit")
    history.run(BlockIpCommand(firewall, "2001:DB8::1"))
    assert firewall.blocked == {"2001:db8::1"}
    history.undo_last()
    assert firewall.blocked == set()
    assert "commande exécutée block_ip 2001:db8::1" in caplog.text
    assert "commande annulée block_ip 2001:db8::1" in caplog.text
