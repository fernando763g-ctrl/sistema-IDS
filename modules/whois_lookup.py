from pathlib import Path
import subprocess
import re

BASE_DIR = Path(__file__).resolve().parent.parent

REPORT_FILE = BASE_DIR / "reports" / "reportes_generados.txt"


def obtener_info_ip(ip):
    try:
        resultado = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=15
        )

        return resultado.stdout

    except Exception as e:
        return f"Error: {e}"


def obtener_abuse_contact(ip):

    whois_data = obtener_info_ip(ip)

    patron_email = r"OrgAbuseEmail:\s*(.+)"
    patron_phone = r"OrgAbusePhone:\s*(.+)"

    email = "No encontrado"
    telefono = "No encontrado"

    email_match = re.search(
        patron_email,
        whois_data,
        re.IGNORECASE
    )

    telefono_match = re.search(
        patron_phone,
        whois_data,
        re.IGNORECASE
    )

    if email_match:
        email = email_match.group(1).strip()

    if telefono_match:
        telefono = telefono_match.group(1).strip()

    return email, telefono

def generar_reporte(ip):

    informacion = obtener_info_ip(ip)

    with open(REPORT_FILE, "a") as archivo:

        archivo.write("\n")
        archivo.write("=" * 60 + "\n")
        archivo.write(f"IP ANALIZADA: {ip}\n")
        archivo.write("=" * 60 + "\n")

        archivo.write(informacion)
        archivo.write("\n")
