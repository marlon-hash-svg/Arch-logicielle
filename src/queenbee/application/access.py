"""Contrôle d'accès : Proxy de lecture devant le dépôt des incidents.

Le Proxy expose exactement le même contrat que l'objet protégé (`IncidentRepository`) :
le client n'a rien à changer, et aucun appel ne passe sans vérification du rôle.
"""

from __future__ import annotations

import logging
from uuid import UUID

from queenbee.application.ports import IncidentRepository
from queenbee.application.services import AccessDeniedError
from queenbee.domain.model import Incident, Principal

_audit = logging.getLogger("queenbee.audit")
READ_ROLES = frozenset({"viewer", "analyst"})


class IncidentReadProxy:
    """Procuration : lecture pour `viewer` ou `analyst`, écriture pour `analyst` seulement."""

    def __init__(self, inner: IncidentRepository, who: Principal) -> None:
        self._inner = inner
        self._who = who
        self.denied = 0

    def _require(self, roles: frozenset[str], action: str) -> None:
        if not roles & self._who.roles:
            self.denied += 1
            _audit.warning("refus %s user=%s", action, self._who.user)
            raise AccessDeniedError(self._who.user)

    def add(self, incident: Incident) -> None:
        """Enregistre un incident (analyste seulement)."""
        self._require(frozenset({"analyst"}), "add")
        self._inner.add(incident)

    def get(self, incident_id: UUID) -> Incident | None:
        """Lit un incident (lecteur ou analyste)."""
        self._require(READ_ROLES, "get")
        return self._inner.get(incident_id)

    def save(self, incident: Incident) -> None:
        """Persiste un incident (analyste seulement)."""
        self._require(frozenset({"analyst"}), "save")
        self._inner.save(incident)

    def list_open(self) -> list[Incident]:
        """Liste les incidents ouverts (lecteur ou analyste)."""
        self._require(READ_ROLES, "list_open")
        return self._inner.list_open()
