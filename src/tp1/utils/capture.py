from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger

import re
import subprocess
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
            # ici ce qui est important c'est prn=self._analyse, qui appelle la méthode analyse pour chaque paquet capturé
            scapy.sniff(iface=self.interface, prn=self._analyse, store=False)

    def _analyse(self, packet) -> None:
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
        # On n'inspecte que les payloads en clair sur des ports HTTP connus
        HTTP_PORTS = {80, 8080, 8000, 8888}
        is_http = (
            packet.haslayer(scapy.TCP)
            and (
                packet[scapy.TCP].dport in HTTP_PORTS
                or packet[scapy.TCP].sport in HTTP_PORTS
            )
        )
        if is_http and packet.haslayer(scapy.Raw):
            raw = packet[scapy.Raw].load
            # Ignorer les payloads binaires : au moins 80% de caractères imprimables
            printable_ratio = sum(0x20 <= b < 0x7F for b in raw) / len(raw)
            if printable_ratio >= 0.8:
                payload = raw.decode(errors="ignore")
                if SQL_PATTERN.search(payload):
                    src = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "unknown"
                    alert = f"[SQL INJECTION] src={src} | payload={payload[:120]!r}"
                    logger.warning(alert)
                    self.alerts.append(alert)
                    self._block_ip(src)

        # --- Détection ARP spoofing ---
        # Un ARP reply (op=2) qui annonce une IP déjà connue avec une MAC différente = spoofing
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            known_mac = self.arp_table.get(ip)
            if known_mac and known_mac != mac:
                alert = f"[ARP SPOOFING] {ip} etait {known_mac}, se fait passer pour {mac}"
                logger.warning(alert)
                self.alerts.append(alert)
                self._restore_arp(ip, known_mac)
            else:
                self.arp_table[ip] = mac

    def _block_ip(self, ip: str) -> None:
        """
        Bloque une IP attaquante via pfctl (macOS).
        Nécessite des droits root.
        """
        try:
            # Ajoute une règle de blocage dans la table pfctl "blocked"
            subprocess.run(["pfctl", "-t", "blocked", "-T", "add", ip], check=True)
            logger.warning(f"[REMEDIATION] IP {ip} bloquee via pfctl")
        except Exception as e:
            logger.error(f"[REMEDIATION] Impossible de bloquer {ip} : {e}")

    def _restore_arp(self, ip: str, legitimate_mac: str) -> None:
        """
        Restaure l'entrée ARP légitime en ajoutant une entrée statique.
        Empêche le cache ARP d'être empoisonné.
        Nécessite des droits root.
        """
        try:
            subprocess.run(["arp", "-s", ip, legitimate_mac], check=True)
            logger.warning(f"[REMEDIATION] Entree ARP statique restauree : {ip} -> {legitimate_mac}")
        except Exception as e:
            logger.error(f"[REMEDIATION] Impossible de restaurer l'ARP pour {ip} : {e}")

    def _sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols by packet count (descending)
        """
        # x[1] correspond au count, on trie par count décroissant
        sorted_protocols = sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)
        return "\n".join(f"{proto}: {count} packets" for proto, count in sorted_protocols)

    def _get_all_protocols(self) -> str:
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

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        lines = ["=== Resume IDS ==="]
        lines.append(f"Protocoles detectes :\n{self._sort_network_protocols()}")
        if self.alerts:
            lines.append(f"\n[!] Alertes ({len(self.alerts)}) :")
            lines.extend(f"  {a}" for a in self.alerts)
        else:
            lines.append("\n[OK] Aucune menace detectee.")
        self.summary = "\n".join(lines)
        return self.summary
