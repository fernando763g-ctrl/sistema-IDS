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

ips_detectadas = set()
dominios_detectados = set()
ips_maliciosas_detectadas = set()
ips_forense = set()

ultimo_dominio = "No disponible"


def analizar_paquete(pkt):

    global ultimo_dominio

    if pkt.haslayer(DNSQR):

        dominio = (
            pkt[DNSQR]
            .qname
            .decode(errors="ignore")
            .rstrip(".")
        )

        ultimo_dominio = dominio

        if dominio not in dominios_detectados:

            dominios_detectados.add(dominio)

            print(f"[DNS] {dominio}")

            guardar_dns(dominio)

    if IP not in pkt:
        return

    ip_origen = pkt[IP].src
    ip_destino = pkt[IP].dst

    if Ether in pkt:
        mac_origen = pkt[Ether].src.lower()
    else:
        mac_origen = "desconocida"

    if (
        verificar_ip(ip_destino)
        and
        ip_destino not in ips_maliciosas_detectadas
    ):

        ips_maliciosas_detectadas.add(
            ip_destino
        )

        ips_forense.add(
            ip_destino
        )

        print("\n========================")
        print("    EMERGENCIA IDS")
        print("========================")
        print(f"IP PELIGROSA: {ip_destino}")
        print("RIESGO: Virus/Botnet")
        print("========================\n")

        enviar_emergencia(
            ip_destino
        )

    if not ip_origen.startswith(
        "192.168.100."
    ):
        return

    if ip_origen in ips_detectadas:
        return

    ips_detectadas.add(ip_origen)

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
        print(f"DNS: {ultimo_dominio}")
        print("========================\n")

        guardar_alerta(
            f"{ip_origen} | {mac_origen}"
        )

        enviar_alerta(
            ip_origen,
            mac_origen,
            ultimo_dominio
        )


def capturar_paquetes():

    print("\nMonitoreando red local...")
    print("Presione CTRL+C para detener\n")

    try:

        sniff(
            iface="enp0s3",
            prn=analizar_paquete,
            store=False
        )

    except KeyboardInterrupt:

        print("\n========================")
        print(" GENERANDO REPORTE FORENSE")
        print("========================\n")

        if len(ips_forense) == 0:

            print(
                "No se detectaron IPs peligrosas."
            )

            return

        for ip in ips_forense:

            try:

                generar_reporte(ip)

                reporte = obtener_info_ip(ip)

                abuse_email, abuse_phone = (
                    obtener_abuse_contact(ip)
                )

                enviar_reporte_forense(
                    ip,
                    reporte,
                    abuse_email,
                    abuse_phone
                )

                print(
                    f"[OK] Reporte forense enviado para {ip}"
                )

            except Exception as e:

                print(
                    f"[ERROR] {ip}: {e}"
                )

        print(
            "\nMonitoreo finalizado."
        )
