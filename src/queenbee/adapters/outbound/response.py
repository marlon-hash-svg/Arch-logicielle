"""Réponse à incident : pare-feu et pattern Commande (action validée, tracée, annulable)."""

from __future__ import annotations

import ipaddress
import logging
from typing import Protocol

from queenbee.application.ports import Firewall
from queenbee.domain.model import DomainError

_audit = logging.getLogger("queenbee.audit")


class InMemoryFirewall:
    """Pare-feu en mémoire : la liste de blocage est un simple ensemble."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def block(self, ip: str) -> None:
        """Ajoute l'IP à la liste de blocage."""
        self.blocked.add(ip)

    def unblock(self, ip: str) -> None:
        """Retire l'IP de la liste de blocage."""
        self.blocked.discard(ip)


class Command(Protocol):
    """Une action réversible."""

    def execute(self) -> None:
        """Applique l'action."""
        ...

    def undo(self) -> None:
        """Annule l'action."""
        ...


class BlockIpCommand:
    """Bloquer une IP : la cible est validée dès la construction, avant tout appel au pare-feu."""

    def __init__(self, firewall: Firewall, ip: str) -> None:
        try:
            self.ip = str(ipaddress.ip_address(ip))  # forme canonique, aucun caractère en trop
        except ValueError as exc:
            raise DomainError(str(exc)) from exc
        self._firewall = firewall

    def execute(self) -> None:
        """Bloque l'IP."""
        self._firewall.block(self.ip)

    def undo(self) -> None:
        """Débloque l'IP."""
        self._firewall.unblock(self.ip)

    def __str__(self) -> str:
        return f"block_ip {self.ip}"


class CommandHistory:
    """Exécute les commandes, les trace dans l'audit et permet d'annuler la dernière."""

    def __init__(self) -> None:
        self._done: list[Command] = []

    def run(self, command: Command) -> None:
        """Exécute puis mémorise la commande."""
        command.execute()
        self._done.append(command)
        _audit.info("commande exécutée %s", command)

    def undo_last(self) -> None:
        """Annule la dernière commande exécutée."""
        if not self._done:
            raise DomainError("aucune commande à annuler")
        command = self._done.pop()
        command.undo()
        _audit.info("commande annulée %s", command)
