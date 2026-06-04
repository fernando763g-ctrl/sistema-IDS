from pathlib import Path
from dotenv import load_dotenv
from email.mime.text import MIMEText
import smtplib
import os

# ==========================================
# CONFIGURACION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(
    BASE_DIR / "config" / ".env"
)

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")


# ==========================================
# ALERTA NORMAL
# ==========================================

def enviar_alerta(ip):

    asunto = "ALERTA IDS - IP NO AUTORIZADA"

    mensaje = f"""
Se detecto una IP no autorizada.

IP detectada:
{ip}

Favor de revisar inmediatamente.
"""

    try:

        correo = MIMEText(
            mensaje,
            "plain",
            "utf-8"
        )

        correo["Subject"] = asunto
        correo["From"] = EMAIL_USER
        correo["To"] = ADMIN_EMAIL

        servidor = smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT
        )

        servidor.starttls()

        servidor.login(
            EMAIL_USER,
            EMAIL_PASSWORD
        )

        servidor.send_message(correo)

        servidor.quit()

        print("[OK] Correo de alerta enviado.")

    except Exception as e:

        print(f"[ERROR SMTP] {e}")


# ==========================================
# ALERTA DE EMERGENCIA
# ==========================================

def enviar_emergencia(ip):

    asunto = "EMERGENCIA IDS - IP MALICIOSA DETECTADA"

    mensaje = f"""
Se detecto una conexion hacia una IP clasificada como peligrosa.

IP Detectada:
{ip}

Riesgo:
Virus / Botnet

Accion recomendada:
Revisar inmediatamente el equipo y la comunicacion detectada.
"""

    try:

        correo = MIMEText(
            mensaje,
            "plain",
            "utf-8"
        )

        correo["Subject"] = asunto
        correo["From"] = EMAIL_USER
        correo["To"] = ADMIN_EMAIL

        servidor = smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT
        )

        servidor.starttls()

        servidor.login(
            EMAIL_USER,
            EMAIL_PASSWORD
        )

        servidor.send_message(correo)

        servidor.quit()

        print("[OK] Correo de emergencia enviado.")

    except Exception as e:

        print(f"[ERROR SMTP] {e}")


# ==========================================
# REPORTE FORENSE
# ==========================================

def enviar_reporte_forense(
    ip,
    reporte,
    abuse_email,
    abuse_phone
):

    asunto = "REPORTE FORENSE IDS"

    mensaje = f"""
Se detecto una IP peligrosa.

IP Detectada:
{ip}

Correo de abuso:
{abuse_email}

Telefono de abuso:
{abuse_phone}

Resumen Whois:

{reporte}
"""

    try:

        correo = MIMEText(
            mensaje,
            "plain",
            "utf-8"
        )

        correo["Subject"] = asunto
        correo["From"] = EMAIL_USER
        correo["To"] = ADMIN_EMAIL

        servidor = smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT
        )

        servidor.starttls()

        servidor.login(
            EMAIL_USER,
            EMAIL_PASSWORD
        )

        servidor.send_message(correo)

        servidor.quit()

        print("[OK] Reporte forense enviado.")

    except Exception as e:

        print(f"[ERROR SMTP] {e}")
