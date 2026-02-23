from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger

import re
import scapy.all as scapy


# Patterns courants d'injection SQL, cependant ce n'est pas la meilleure méthode pour détecter les injections SQL, c'est juste un exemple simple pour le TP. 
# Voir : https://security.stackexchange.com/questions/203843/is-it-possible-to-detect-100-of-sqli-with-a-simple-regex pour + d'infos sur les limites de cette approche.
SQL_PATTERN = re.compile(
    r"(union\s+select|drop\s+table|insert\s+into|select\s+\*|or\s+1=1|--|;--)",
    re.IGNORECASE,
)


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.alerts: list[str] = []           # alertes IDS détectées
        self.protocols: dict[str, int] = {}   # comptage par protocole
        self.arp_table: dict[str, str] = {}   # {ip: mac} pour détecter l'ARP spoofing
        self._pcap_writer = None

    def capture_traffic(self) -> None:
        """
        Capture le trafic réseau en temps réel.
        Chaque paquet est analysé à la volée et écrit dans un fichier pcap.
        Arrêt avec Ctrl+C.
        """
        pcap_file = "capture.pcap"
        logger.info(f"Démarrage de la capture sur {self.interface} → {pcap_file}")

        with scapy.PcapWriter(pcap_file, append=False, sync=True) as writer:
            self._pcap_writer = writer
            # ici ce qui est important c'est prn=self.analyse, qui appelle la méthode analyse pour chaque paquet capturé
            scapy.sniff(iface=self.interface, prn=self.analyse, store=False)

    def analyse(self, packet) -> None:
        """
        Callback appelé par scapy pour chaque paquet capturé.
        - Écrit le paquet dans le fichier pcap
        - Compte les protocoles
        - Détecte les injections SQL dans les payloads TCP/UDP
        - Détecte l'ARP spoofing
        """
        # Écriture en temps réel dans le pcap
        if self._pcap_writer:
            self._pcap_writer.write(packet)

        # Comptage des protocoles
        proto = packet.lastlayer().name
        self.protocols[proto] = self.protocols.get(proto, 0) + 1

        # --- Détection injection SQL ---
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors="ignore")
            if SQL_PATTERN.search(payload):
                src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "unknown"
                alert = f"[SQL INJECTION] src={src} | payload={payload[:120]!r}"
                logger.warning(alert)
                self.alerts.append(alert)

        # --- Détection ARP spoofing ---
        # Un ARP reply (op=2) qui annonce une IP déjà connue avec une MAC différente = spoofing
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            known_mac = self.arp_table.get(ip)
            if known_mac and known_mac != mac:
                alert = f"[ARP SPOOFING] {ip} était {known_mac}, se fait passer pour {mac}"
                logger.warning(alert)
                self.alerts.append(alert)
            else:
                self.arp_table[ip] = mac

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols by packet count (descending)
        """
        # x[1] correspond au count, on trie par count décroissant
        sorted_protocols = sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)
        return "\n".join(f"{proto}: {count} packets" for proto, count in sorted_protocols)

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return "\n".join(f"{proto}: {count} packets" for proto, count in self.protocols.items())

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        lines = ["=== Résumé IDS ==="]
        lines.append(f"Protocoles détectés :\n{self.sort_network_protocols()}")
        if self.alerts:
            lines.append(f"\n⚠ Alertes ({len(self.alerts)}) :")
            lines.extend(f"  {a}" for a in self.alerts)
        else:
            lines.append("\n✓ Aucune menace détectée.")
        self.summary = "\n".join(lines)
        return self.summary
