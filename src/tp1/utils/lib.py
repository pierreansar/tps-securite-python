import scapy.all as scapy


def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice
    """

    # Lister toutes les interfaces réseau disponibles
    interfaces = scapy.get_if_list()

    print("Interfaces réseau disponibles :")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")

    while True:
        try:
            choice = int(input("Choisissez une interface (numéro) : "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            print(f"Veuillez entrer un numéro entre 0 et {len(interfaces) - 1}.")
        except ValueError:
            print("Entrée invalide, veuillez entrer un numéro.")