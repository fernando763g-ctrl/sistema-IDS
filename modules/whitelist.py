from pathlib import Path
import socket
import uuid

# ==========================
# RUTAS
# ==========================

BASE_DIR = Path(__file__).resolve().parent.parent

IPS_FILE = BASE_DIR / "whitelist" / "ips.txt"
MACS_FILE = BASE_DIR / "whitelist" / "macs.txt"


# ==========================
# OBTENER IP LOCAL
# ==========================

def obtener_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


# ==========================
# OBTENER MAC LOCAL
# ==========================

def obtener_mac():
    mac = ':'.join(
        ['{:02x}'.format((uuid.getnode() >> elementos) & 0xff)
         for elementos in range(0, 8 * 6, 8)][::-1]
    )

    return mac


# ==========================
# REGISTRAR DISPOSITIVO
# ==========================

def registrar():

    ip = obtener_ip()
    mac = obtener_mac()

    print("\n=== DISPOSITIVO DETECTADO ===")
    print(f"IP : {ip}")
    print(f"MAC: {mac}")

    respuesta = input(
        "\n¿Desea registrar este dispositivo? (S/N): "
    ).upper()

    if respuesta == "S":

        with open(IPS_FILE, "a") as archivo:
            archivo.write(ip + "\n")

        with open(MACS_FILE, "a") as archivo:
            archivo.write(mac + "\n")

        print("\n[OK] Dispositivo registrado.")

    else:
        print("\nOperación cancelada.")


# ==========================
# CONSULTAR LISTA BLANCA
# ==========================

def consultar():

    print("\n=== IPS AUTORIZADAS ===")

    try:
        with open(IPS_FILE, "r") as archivo:
            contenido = archivo.read()

            if contenido.strip():
                print(contenido)
            else:
                print("Sin registros.")

    except FileNotFoundError:
        print("Archivo no encontrado.")

    print("\n=== MACS AUTORIZADAS ===")

    try:
        with open(MACS_FILE, "r") as archivo:
            contenido = archivo.read()

            if contenido.strip():
                print(contenido)
            else:
                print("Sin registros.")

    except FileNotFoundError:
        print("Archivo no encontrado.")


# ==========================
# ELIMINAR DISPOSITIVO
# ==========================

def eliminar():

    with open(IPS_FILE, "r") as archivo:
        ips = [linea.strip() for linea in archivo if linea.strip()]

    if not ips:
        print("No existen dispositivos registrados.")
        return

    print("\n=== DISPOSITIVOS REGISTRADOS ===")

    for i, ip in enumerate(ips, start=1):
        print(f"{i}. {ip}")

    try:
        opcion = int(
            input("\nSeleccione el número a eliminar: ")
        )

        if opcion < 1 or opcion > len(ips):
            print("Opción inválida.")
            return

        ips.pop(opcion - 1)

        with open(IPS_FILE, "w") as archivo:
            for ip in ips:
                archivo.write(ip + "\n")

        print("\n[OK] Registro eliminado.")

    except ValueError:
        print("Debe ingresar un número.")


# ==========================
# VALIDAR
# ==========================

def validar(ip, mac):

    with open(IPS_FILE, "r") as archivo:
        ips = [linea.strip() for linea in archivo]

    with open(MACS_FILE, "r") as archivo:
        macs = [linea.strip().lower() for linea in archivo]

    return ip in ips and mac.lower() in macs
