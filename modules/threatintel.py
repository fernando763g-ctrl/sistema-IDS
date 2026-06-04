from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

BLACKLIST_FILE = (
    BASE_DIR /
    "blacklist" /
    "malicious_ips.txt"
)


def cargar_lista_negra():

    try:

        with open(BLACKLIST_FILE, "r") as archivo:

            return {
                linea.strip()
                for linea in archivo
                if linea.strip()
            }

    except FileNotFoundError:

        return set()


def verificar_ip(ip):

    lista_negra = cargar_lista_negra()

    return ip in lista_negra
