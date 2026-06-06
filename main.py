from modules.monitor import capturar_paquetes
from modules.whitelist import (
    registrar,
    consultar,
    eliminar
)


# ==========================
# VER REPORTES
# ==========================

def ver_reportes():

    while True:

        dns_total = 0
        alertas_total = 0
        incidentes_total = 0

        try:

            with open("logs/dns.log", "r") as archivo:
                dns_total = len(
                    archivo.readlines()
                )

        except:
            pass

        try:

            with open("logs/alerts.log", "r") as archivo:
                alertas_total = len(
                    archivo.readlines()
                )

        except:
            pass

        try:

            with open(
                "reports/reportes_generados.txt",
                "r"
            ) as archivo:

                contenido = archivo.read()

                incidentes_total = contenido.count(
                    "IP ANALIZADA:"
                )

        except:
            pass

        print("\n==============================")
        print("       RESUMEN IDS")
        print("==============================")

        print(
            f"Dominios detectados : {dns_total}"
        )

        print(
            f"Alertas generadas   : {alertas_total}"
        )

        print(
            f"Incidentes forenses : {incidentes_total}"
        )

        print("\n1. Ver DNS")
        print("2. Ver Alertas")
        print("3. Ver Forense")
        print("4. Regresar")

        opcion = input(
            "\nSeleccione una opción: "
        )

        if opcion == "1":

            print("\n===== DNS =====")

            try:

                with open(
                    "logs/dns.log",
                    "r"
                ) as archivo:

                    print(
                        archivo.read()
                    )

            except:

                print(
                    "No existen registros DNS."
                )

        elif opcion == "2":

            print("\n===== ALERTAS =====")

            try:

                with open(
                    "logs/alerts.log",
                    "r"
                ) as archivo:

                    print(
                        archivo.read()
                    )

            except:

                print(
                    "No existen alertas."
                )

        elif opcion == "3":

            print("\n===== FORENSE =====")

            try:

                with open(
                    "reports/reportes_generados.txt",
                    "r"
                ) as archivo:

                    print(
                        archivo.read()
                    )

            except:

                print(
                    "No existen reportes."
                )

        elif opcion == "4":

            break

        else:

            print(
                "\nOpción inválida."
            )

# ==========================
# MENU PRINCIPAL
# ==========================

def mostrar_menu():

    while True:

        print("\n==============================")
        print("      IDS INSTITUCIONAL")
        print("==============================")
        print("1. Registrar dispositivo")
        print("2. Ver lista blanca")
        print("3. Eliminar dispositivo")
        print("4. Iniciar monitoreo IDS")
        print("5. Ver reportes")
        print("6. Salir")

        opcion = input("\nSeleccione una opción: ")

        # ==========================
        # REGISTRAR
        # ==========================

        if opcion == "1":

            registrar()

        # ==========================
        # CONSULTAR
        # ==========================

        elif opcion == "2":

            consultar()

        # ==========================
        # ELIMINAR
        # ==========================

        elif opcion == "3":

            eliminar()

        # ==========================
        # MONITOREO
        # ==========================

        elif opcion == "4":

            capturar_paquetes()

        # ==========================
        # REPORTES
        # ==========================

        elif opcion == "5":

            ver_reportes()

        # ==========================
        # SALIR
        # ==========================

        elif opcion == "6":

            print("\nSaliendo del IDS...")
            break

        else:

            print("\nOpción inválida")


# ==========================
# MAIN
# ==========================

if __name__ == "__main__":

    mostrar_menu()
