"""Dépôts d'incidents : en mémoire (tests) et SQLite (production), même contrat."""

from __future__ import annotations

import sqlite3
from uuid import UUID

from queenbee.domain.model import Alert, Incident, IncidentStatus, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incident (
    id TEXT PRIMARY KEY,
    rule TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    severity INTEGER NOT NULL,
    detail TEXT NOT NULL,
    status TEXT NOT NULL
)
"""
_INSERT = (
    "INSERT INTO incident (id, rule, source_ip, severity, detail, status) VALUES (?, ?, ?, ?, ?, ?)"
)
_SELECT = "SELECT id, rule, source_ip, severity, detail, status FROM incident"


class InMemoryIncidentRepository:
    """Dépôt en mémoire : rapide, sans base, pour les tests et la démonstration."""

    def __init__(self) -> None:
        self._items: dict[UUID, Incident] = {}

    def add(self, incident: Incident) -> None:
        """Enregistre un nouvel incident."""
        self._items[incident.id] = incident

    def get(self, incident_id: UUID) -> Incident | None:
        """Renvoie l'incident, ou None s'il n'existe pas."""
        return self._items.get(incident_id)

    def save(self, incident: Incident) -> None:
        """Persiste les changements d'un incident existant."""
        self._items[incident.id] = incident

    def list_open(self) -> list[Incident]:
        """Renvoie les incidents qui ne sont pas clos."""
        return [i for i in self._items.values() if i.status is not IncidentStatus.CLOSED]


class SqliteIncidentRepository:
    """Dépôt SQLite : toutes les requêtes sont paramétrées, aucune donnée dans le code SQL."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._conn.execute(_SCHEMA)

    def add(self, incident: Incident) -> None:
        """Enregistre un nouvel incident."""
        a = incident.alert
        with self._conn:
            self._conn.execute(
                _INSERT,
                (str(incident.id), a.rule, a.source_ip, int(a.severity), a.detail, incident.status),
            )

    def get(self, incident_id: UUID) -> Incident | None:
        """Renvoie l'incident, ou None s'il n'existe pas."""
        row = self._conn.execute(
            _SELECT + " WHERE id = ?",
            (str(incident_id),),
        ).fetchone()
        return None if row is None else _to_incident(row)

    def save(self, incident: Incident) -> None:
        """Persiste le statut d'un incident existant."""
        with self._conn:
            self._conn.execute(
                "UPDATE incident SET status = ? WHERE id = ?",
                (incident.status, str(incident.id)),
            )

    def list_open(self) -> list[Incident]:
        """Renvoie les incidents qui ne sont pas clos."""
        rows = self._conn.execute(
            _SELECT + " WHERE status != ?",
            (IncidentStatus.CLOSED,),
        ).fetchall()
        return [_to_incident(r) for r in rows]


def _to_incident(row: tuple[str, str, str, int, str, str]) -> Incident:
    # Relire = reconstruire via les constructeurs : une ligne altérée en base est refusée.
    incident_id, rule, ip, severity, detail, status = row
    alert = Alert(rule, ip, Severity(severity), detail)
    return Incident(alert, UUID(incident_id), IncidentStatus(status))
