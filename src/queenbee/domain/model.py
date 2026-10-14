"""Objets métier de Queen Bee : un objet invalide ne peut pas exister.

Chaque objet-valeur est figé et se valide à la construction ; l'incident est la seule entité
mutable, et ses changements d'état passent par une table de transitions autorisées.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Final
from uuid import UUID, uuid4

MAX_USERNAME: Final = 64
ALLOWED_ACTIONS: Final = frozenset({"login_failed", "login_ok", "port_probe"})
_USERNAME_RE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")


class DomainError(ValueError):
    """Une règle métier est violée : la donnée est refusée, jamais corrigée en silence."""


def _check_ip(value: str) -> None:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise DomainError("adresse IP invalide") from exc


class Severity(IntEnum):
    """Gravité d'une alerte, ordonnée de la plus faible à la plus forte."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IncidentStatus(StrEnum):
    """Étapes du cycle de vie d'un incident."""

    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    CLOSED = "closed"


_TRANSITIONS: Final[dict[IncidentStatus, frozenset[IncidentStatus]]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.TRIAGED}),
    IncidentStatus.TRIAGED: frozenset({IncidentStatus.CONTAINED, IncidentStatus.CLOSED}),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.CLOSED}),
    IncidentStatus.CLOSED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Un événement de sécurité remonté par un agent, validé dès sa construction."""

    source_ip: str
    username: str
    action: str
    timestamp: datetime

    def __post_init__(self) -> None:
        _check_ip(self.source_ip)
        if len(self.username) > MAX_USERNAME:  # borner avant la regex
            raise DomainError("nom d'utilisateur trop long")
        if not _USERNAME_RE.fullmatch(self.username):
            raise DomainError("nom d'utilisateur invalide")
        if self.action not in ALLOWED_ACTIONS:
            raise DomainError("action inconnue")
        if self.timestamp.tzinfo is None:
            raise DomainError("horodatage sans fuseau")


@dataclass(frozen=True, slots=True)
class Alert:
    """Le résultat d'une règle de détection : quelle règle, quelle IP, quelle gravité."""

    rule: str
    source_ip: str
    severity: Severity
    detail: str

    def __post_init__(self) -> None:
        if not self.rule:
            raise DomainError("règle absente")
        _check_ip(self.source_ip)
        if self.severity not in Severity:
            raise DomainError("gravité inconnue")


@dataclass(slots=True)
class Incident:
    """Incident ouvert depuis une alerte ; son statut ne suit que les transitions permises."""

    alert: Alert
    id: UUID = field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.OPEN

    def transition_to(self, new: IncidentStatus) -> None:
        """Passe au statut `new`, ou lève DomainError si la transition est interdite."""
        if new not in _TRANSITIONS[self.status]:
            raise DomainError(f"transition interdite : {self.status} -> {new}")
        self.status = new
