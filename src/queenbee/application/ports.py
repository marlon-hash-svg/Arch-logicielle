"""Ports : ce dont le cœur a besoin, exprimé en contrats (`typing.Protocol`).

Le domaine et les cas d'usage dépendent de ces contrats, jamais de sqlite3 ni de smtplib :
les adaptateurs concrets (base, e-mail, mémoire pour les tests) sont branchés au démarrage.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from queenbee.domain.model import Alert, Incident


class IncidentRepository(Protocol):
    """Stockage des incidents (remplace `DB.execute(f"INSERT ...")` du script hérité)."""

    def add(self, incident: Incident) -> None:
        """Enregistre un nouvel incident."""
        ...

    def get(self, incident_id: UUID) -> Incident | None:
        """Renvoie l'incident, ou None s'il n'existe pas."""
        ...

    def save(self, incident: Incident) -> None:
        """Persiste les changements d'un incident existant."""
        ...

    def list_open(self) -> list[Incident]:
        """Renvoie les incidents qui ne sont pas clos."""
        ...


class Notifier(Protocol):
    """Diffusion d'une alerte (remplace `smtplib.SMTP(...)` codé en dur dans le script hérité)."""

    def notify(self, alert: Alert) -> None:
        """Transmet l'alerte ; lève une exception en cas d'échec, ne l'avale jamais."""
        ...


class Firewall(Protocol):
    """Action sur le filtrage réseau : bloquer ou débloquer une adresse IP déjà validée."""

    def block(self, ip: str) -> None:
        """Ajoute l'IP à la liste de blocage."""
        ...

    def unblock(self, ip: str) -> None:
        """Retire l'IP de la liste de blocage."""
        ...
