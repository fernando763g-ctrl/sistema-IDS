from pathlib import Path
from dotenv import load_dotenv
from email.mime.text import MIMEText
from datetime import datetime
import smtplib
import os

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(
    BASE_DIR / "config" / ".env"
)

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")


def enviar_alerta(ip, mac, dominio="No disponible"):

    asunto = "ALERTA IDS - DISPOSITIVO NO AUTORIZADO"

    fecha = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    mensaje = f"""
ALERTA IDS - DISPOSITIVO NO AUTORIZADO

Fecha:
{fecha}

Dispositivo detectado:

IP  : {ip}
MAC : {mac}

Dominio detectado:
{dominio}

Estado:
NO AUTORIZADO

Descripcion:
Se detectó un dispositivo que ha comenzado a generar tráfico en la red institucional y no se encuentra registrado en la lista blanca.

Acciones recomendadas:

1. Verificar la identidad del usuario.
2. Confirmar si el dispositivo pertenece a la organización.
3. Registrar el dispositivo en la lista blanca únicamente si está autorizado.

Sistema:
IDS Institucional
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
            SMTP_PORT,
            timeout=10
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


def enviar_emergencia(ip):

    asunto = "EMERGENCIA IDS - IP MALICIOSA DETECTADA"

    fecha = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    mensaje = f"""
EMERGENCIA IDS

Fecha:
{fecha}

IP Detectada:
{ip}

Riesgo:
Virus / Botnet

Descripcion:
Se detectó una conexión hacia una IP incluida en la lista negra del sistema.

Acciones recomendadas:

1. Aislar el dispositivo afectado.
2. Revisar el tráfico de red.
3. Analizar posibles indicadores de compromiso.

Sistema:
IDS Institucional
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
            SMTP_PORT,
            timeout=10
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


def enviar_reporte_forense(
    ip,
    reporte,
    abuse_email,
    abuse_phone
):

    asunto = "REPORTE FORENSE IDS"

    mensaje = f"""
REPORTE FORENSE IDS

IP Detectada:
{ip}

Correo de abuso:
{abuse_email}

Telefono de abuso:
{abuse_phone}

Resumen Whois:

{reporte[:3000]}

Accion recomendada:

Utilice el correo de abuso proporcionado para reportar la actividad sospechosa al proveedor correspondiente.
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
            SMTP_PORT,
            timeout=10
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
