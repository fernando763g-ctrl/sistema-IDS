from scapy.all import sniff, IP, DNSQR, Ether

from modules.whitelist import validar
from modules.logger import guardar_alerta, guardar_dns

from modules.mailer import (
    enviar_alerta,
    enviar_emergencia,
    enviar_reporte_forense
)

from modules.threatintel import verificar_ip

from modules.whois_lookup import (
    obtener_info_ip,
    obtener_abuse_contact,
    generar_reporte
)

# =====================================
# EVITAR EVENTOS REPETIDOS
# =====================================

ips_detectadas = set()
dominios_detectados = set()
ips_maliciosas_detectadas = set()


# =====================================
# ANALIZAR PAQUETE
# =====================================

def analizar_paquete(pkt):

    # =====================================
    # MONITOR DNS
    # =====================================

    if pkt.haslayer(DNSQR):

        dominio = (
            pkt[DNSQR]
            .qname
            .decode(errors="ignore")
            .rstrip(".")
        )

        if dominio not in dominios_detectados:

            dominios_detectados.add(dominio)

            print(f"[DNS] {dominio}")

            guardar_dns(dominio)

    # =====================================
    # VALIDAR CAPA IP
    # =====================================

    if IP not in pkt:
        return

    ip_origen = pkt[IP].src

    # =====================================
    # OBTENER MAC ORIGEN
    # =====================================

    if Ether in pkt:
        mac_origen = pkt[Ether].src
    else:
        mac_origen = "DESCONOCIDA"

    # =====================================
    # THREAT INTELLIGENCE
    # =====================================

    if ip_origen not in ips_maliciosas_detectadas:

        if verificar_ip(ip_origen):

            ips_maliciosas_detectadas.add(ip_origen)

            print("\n========================")
            print("    EMERGENCIA IDS")
            print("========================")
            print(f"IP MALICIOSA: {ip_origen}")
            print("========================\n")

            enviar_emergencia(ip_origen)

            generar_reporte(ip_origen)

            reporte = obtener_info_ip(ip_origen)

            abuse_email, abuse_phone = (
                obtener_abuse_contact(ip_origen)
            )

            enviar_reporte_forense(
                ip_origen,
                reporte[:3000],
                abuse_email,
                abuse_phone
            )

    # =====================================
    # SOLO RED LOCAL
    # =====================================

    if not ip_origen.startswith("192.168.1."):
        return

    if ip_origen in ips_detectadas:
        return

    ips_detectadas.add(ip_origen)

    # =====================================
    # LISTA BLANCA IP + MAC
    # =====================================

    if validar(ip_origen, mac_origen):

        print(
            f"[OK] Dispositivo autorizado: "
            f"{ip_origen} | {mac_origen}"
        )

    else:

        print("\n========================")
        print("      ALERTA IDS")
        print("========================")
        print(f"IP : {ip_origen}")
        print(f"MAC: {mac_origen}")
        print("========================\n")

        guardar_alerta(
            f"{ip_origen} | {mac_origen}"
        )

        enviar_alerta(ip_origen)


# =====================================
# CAPTURA DE PAQUETES
# =====================================

def capturar_paquetes():

    print("\nMonitoreando red local...")
    print("Presione CTRL+C para detener\n")

    sniff(
        iface="enp0s3",
        prn=analizar_paquete,
        store=False
    )
