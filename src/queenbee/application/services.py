"""Cas d'usage de Queen Bee : ils orchestrent le domaine via les ports, sans rien de technique."""

from __future__ import annotations

from collections.abc import Sequence

from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import Incident, SecurityEvent
from queenbee.domain.rules import DetectionRule


class DetectionService:
    """Évalue les événements, ouvre un incident par alerte et prévient chaque abonné."""

    def __init__(
        self,
        rule: DetectionRule,
        incidents: IncidentRepository,
        notifiers: Sequence[Notifier],
    ) -> None:
        self._rule = rule
        self._incidents = incidents
        self._notifiers = tuple(notifiers)

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Incident]:
        """Renvoie les incidents créés pour ce lot d'événements."""
        created: list[Incident] = []
        for alert in self._rule.evaluate(events):
            incident = Incident(alert)
            self._incidents.add(incident)
            for notifier in self._notifiers:
                notifier.notify(alert)
            created.append(incident)
        return created
