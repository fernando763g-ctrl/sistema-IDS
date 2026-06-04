from modules.monitor import capturar_paquetes
from modules.whitelist import (
    registrar,
    consultar,
    eliminar
)


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
            print("\n[MÓDULO EN CONSTRUCCIÓN]")
            print("Aquí se mostrarán los reportes")

        # ==========================
        # SALIR
        # ==========================
        elif opcion == "6":
            print("\nSaliendo del IDS...")
            break

        else:
            print("\nOpción inválida")


if __name__ == "__main__":
    mostrar_menu()
