"""Cas d'usage de Queen Bee : ils orchestrent le domaine via les ports, sans rien de technique."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from uuid import UUID

from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import DomainError, Incident, IncidentStatus, Principal, SecurityEvent
from queenbee.domain.rules import DetectionRule

_audit = logging.getLogger("queenbee.audit")
_log = logging.getLogger(__name__)


class AccessDeniedError(Exception):
    """L'identité n'a pas le rôle exigé : l'action est refusée, rien n'est modifié."""


class DetectionService:
    """Évalue les événements, ouvre un incident par alerte et prévient chaque abonné (Observer)."""

    def __init__(
        self,
        rule: DetectionRule,
        incidents: IncidentRepository,
        notifiers: Sequence[Notifier],
    ) -> None:
        self._rule = rule
        self._incidents = incidents
        self._notifiers = tuple(notifiers)
        self.notify_failures = 0

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Incident]:
        """Renvoie les incidents créés pour ce lot d'événements."""
        created: list[Incident] = []
        for alert in self._rule.evaluate(events):
            incident = Incident(alert)
            self._incidents.add(incident)
            for notifier in self._notifiers:
                self._notify_one(notifier, incident)
            created.append(incident)
        return created

    def _notify_one(self, notifier: Notifier, incident: Incident) -> None:
        # Décision écrite : un abonné en panne ne prive pas les autres de l'alerte.
        # L'erreur n'est pas avalée : elle est comptée et journalisée avec sa trace.
        try:
            notifier.notify(incident.alert)
        except Exception:
            self.notify_failures += 1
            _log.exception(
                "échec de notification incident=%s abonné=%s", incident.id, type(notifier).__name__
            )


class IncidentService:
    """Cas d'usage sur les incidents : autoriser, vérifier, appliquer la règle, persister."""

    def __init__(self, incidents: IncidentRepository) -> None:
        self._incidents = incidents

    def move(self, who: Principal, incident_id: UUID, to: IncidentStatus) -> Incident:
        """Fait passer un incident au statut `to` ; réservé au rôle `analyst`."""
        if not who.has("analyst"):  # 1. autoriser
            _audit.warning("refus move user=%s incident=%s vers=%s", who.user, incident_id, to)
            raise AccessDeniedError(who.user)
        incident = self._incidents.get(incident_id)  # 2. vérifier
        if incident is None:
            raise DomainError("incident introuvable")
        before = incident.status
        incident.transition_to(to)  # 3. règle métier
        self._incidents.save(incident)  # 4. persister
        _audit.info("move user=%s incident=%s %s->%s", who.user, incident.id, before, to)
        return incident
