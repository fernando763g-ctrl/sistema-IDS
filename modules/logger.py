from pathlib import Path
from datetime import datetime

# ==========================
# RUTAS
# ==========================

BASE_DIR = Path(__file__).resolve().parent.parent

ALERTS_LOG = BASE_DIR / "logs" / "alerts.log"
DNS_LOG = BASE_DIR / "logs" / "dns.log"
INCIDENTS_LOG = BASE_DIR / "logs" / "incidents.log"


# ==========================
# ALERTAS
# ==========================

def guardar_alerta(ip):

    fecha = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(ALERTS_LOG, "a") as archivo:

        archivo.write(
            f"{fecha} | ALERTA | {ip}\n"
        )


# ==========================
# DNS
# ==========================

def guardar_dns(dominio):

    fecha = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(DNS_LOG, "a") as archivo:

        archivo.write(
            f"{fecha} | DNS | {dominio}\n"
        )


# ==========================
# INCIDENTES
# ==========================

def guardar_incidente(texto):

    fecha = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(INCIDENTS_LOG, "a") as archivo:

        archivo.write(
            f"{fecha} | INCIDENTE | {texto}\n"
        )
