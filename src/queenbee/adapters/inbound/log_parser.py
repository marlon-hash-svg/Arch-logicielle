"""Adaptateur : ligne de journal sshd -> `SecurityEvent`.

Ordre défensif : borner la taille, puis une regex ancrée sans répétition imbriquée (temps
linéaire), puis laisser le domaine revalider l'IP, le nom et l'horodatage.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Final

from queenbee.domain.model import DomainError, SecurityEvent

MAX_LINE: Final = 512
_ACTIONS: Final = {"Failed": "login_failed", "Accepted": "login_ok"}
_SSHD_RE: Final = re.compile(
    r"(?P<ts>[0-9T:+.Z-]{19,35}) sshd: (?P<verb>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<user>[^\s]{1,64}) from (?P<ip>[0-9A-Fa-f:.]{2,45})"
)


def parse_sshd_line(line: str) -> SecurityEvent:
    """Traduit une ligne sshd en événement validé, ou lève DomainError."""
    if len(line) > MAX_LINE:
        raise DomainError("ligne trop longue")
    match = _SSHD_RE.fullmatch(line.rstrip("\r\n"))
    if match is None:
        raise DomainError("ligne sshd non reconnue")
    try:
        timestamp = datetime.fromisoformat(match["ts"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(match["ip"], match["user"], _ACTIONS[match["verb"]], timestamp)
