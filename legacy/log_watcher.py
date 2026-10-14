# ruff: noqa
# fmt: off
"""CODE DE DÉPART (issu de « Python Scripting Sécu ») — volontairement MAUVAIS.

Atelier J1-A2 : relever toutes les violations SOLID et de sécurité, puis refactorer.
Ne pas déployer. Ne pas copier ces pratiques.
"""
import os, re, sqlite3, smtplib

DB = sqlite3.connect("incidents.db")
MAX_LINE = 512
# Motif précis et sans répétition imbriquée : utilisateur et IP ont chacun un alphabet et une taille bornés.
SSHD_FAILED = re.compile(
    r"\w{3} [ \d]\d \d\d:\d\d:\d\d \S{1,255} sshd\[\d{1,10}\]: "
    r"Failed password for (?:invalid user )?([A-Za-z_][A-Za-z0-9_.-]{0,63}) "
    r"from ([0-9A-Fa-f:.]{2,45}) port \d{1,5} ssh2"
)

class LogWatcher:                          # God class : lit, parse, détecte, stocke, alerte
    def __init__(self, path):
        self.path = path
        self.counts = {}

    def run(self):
        for line in open(self.path):        # fichier jamais fermé, aucune limite de taille
            if len(line) > MAX_LINE:         # borner avant la regex
                continue
            m = SSHD_FAILED.fullmatch(line.rstrip("\n"))  # ancrée : toute la ligne, rien d'autre
            if m:
                user, ip = m.group(1), m.group(2)
                self.counts[ip] = self.counts.get(ip, 0) + 1
                if self.counts[ip] == 5:
                    # ip vient du log, donc de l'attaquant : le pilote sépare code SQL et données
                    DB.execute("INSERT INTO incidents VALUES (?, ?)", (ip, user))
                    self.alert(ip)

    def alert(self, ip):
        password = os.environ.get("QUEENBEE_SMTP_PASSWORD")   # lu à l'usage, jamais versionné
        if not password:
            raise RuntimeError("QUEENBEE_SMTP_PASSWORD non défini")  # pas de valeur par défaut
        s = smtplib.SMTP("mail.local")
        s.login("queenbee", password)
        s.sendmail("qb@local", "soc@local", f"Brute force from {ip}")

    def report(self, kind):
        if kind == "csv":                    # OCP : chaque format = un elif de plus
            return "\n".join(f"{k},{v}" for k, v in self.counts.items())
        elif kind == "html":
            return "<br>".join(f"{k}:{v}" for k, v in self.counts.items())  # XSS possible
        elif kind == "json":
            return str(self.counts)
