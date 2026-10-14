"""Fabrique abstraite : produit une famille cohérente de composants, « prod » OU « mémoire ».

Un service reçoit une seule fabrique : il ne peut pas mélanger une vraie base et une
fausse notification.
"""

from __future__ import annotations

import sqlite3
from typing import Protocol

from queenbee.adapters.outbound.notifiers import LogNotifier, MemoryNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.ports import IncidentRepository, Notifier


class ComponentFactory(Protocol):
    """Contrat commun aux familles de composants."""

    def repository(self) -> IncidentRepository:
        """Dépôt des incidents de cette famille."""
        ...

    def notifier(self) -> Notifier:
        """Notificateur de cette famille."""
        ...


class InMemoryFactory:
    """Famille « mémoire » : aucune base, aucun réseau ; pour les tests et la démonstration."""

    def repository(self) -> InMemoryIncidentRepository:
        """Dépôt en mémoire."""
        return InMemoryIncidentRepository()

    def notifier(self) -> MemoryNotifier:
        """Notificateur qui garde les alertes en mémoire."""
        return MemoryNotifier()


class ProdFactory:
    """Famille « production » : base SQLite et alertes journalisées vers le SIEM."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def repository(self) -> SqliteIncidentRepository:
        """Dépôt SQLite sur la base configurée."""
        return SqliteIncidentRepository(sqlite3.connect(self._db_path))

    def notifier(self) -> LogNotifier:
        """Notificateur qui journalise les alertes."""
        return LogNotifier()
