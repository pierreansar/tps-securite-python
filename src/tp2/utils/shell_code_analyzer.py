import pylibemu
import os
from capstone import *

from openai import OpenAI

class ShellCodeAnalyzer:
    def __init__(self, shell_code):
        self.shell_code = shell_code

    def get_shellcode_strings(self) -> list[str]:
        """Extrait les chaînes ASCII imprimables du shellcode (longueur >= 4)."""
        strings = []
        current = ""
        for byte in self.shell_code:
            char = chr(byte)
            if char.isprintable() and char != ' ':
                current += char
            else:
                if len(current) >= 4:
                    strings.append(current)
                current = ""
        if len(current) >= 4:
            strings.append(current)
        return strings
    
    def get_pylibemu_analysis(self) -> str:
        emulator = pylibemu.Emulator()
        offset = emulator.shellcode_getpc_test(self.shell_code)
        print(f"[*] Offset GetPC: {offset}")
        emulator.prepare(self.shell_code, offset)
        emulator.test()
        print(emulator.emu_profile_output)
        return emulator.emu_profile_output


    def get_capstone_analysis(self) -> str:
        """
        Désassemble le shellcode avec capstone et retourne une chaîne de caractères lisible en assembleur.
        """
        # Initialisation du désassembleur
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        result = []
        for insn in md.disasm(self.shell_code, 0x1000):
            result.append(f"0x{insn.address:08x}:\t{insn.mnemonic}\t{insn.op_str}")

        self.assembly_code = "\n".join(result)

        return "\n".join(result)
    
    def get_llm_analysis(self) -> str:
        """
        Envoie le shellcode à un LLM (ex: GPT-4) pour obtenir une analyse détaillée de son fonctionnement.
        Enrichit le prompt avec les strings extraites, l'analyse pylibemu et le désassemblage capstone.
        """
        strings = self.get_shellcode_strings()
        pylibemu_output = self.get_pylibemu_analysis()
        capstone_output = self.get_capstone_analysis()

        prompt = f"""## Shellcode brut (hex)
        {self.shell_code.hex()}

        ## Chaînes ASCII extraites (strings)
        {chr(10).join(strings) if strings else "Aucune chaîne trouvée"}

        ## Analyse d'émulation pylibemu
        {pylibemu_output if pylibemu_output else "Aucune sortie d'émulation"}

        ## Désassemblage Capstone (x86 32-bit)
        {capstone_output if capstone_output else "Aucune instruction désassemblée"}
        """

        client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        response = client.responses.create(
            model="gpt-4.1",
            instructions=(
                "Tu es un expert en sécurité informatique spécialisé dans l'analyse de shellcode. "
                "Tu reçois un shellcode x86 32-bit accompagné de plusieurs analyses préliminaires : "
                "les chaînes ASCII extraites, la sortie d'émulation pylibemu (appels système et fonctions détectés), "
                "et le désassemblage complet en assembleur via Capstone. "
                "À partir de toutes ces informations, fournis une analyse détaillée et structurée qui couvre : "
                "1) l'objectif général du shellcode, "
                "2) les techniques utilisées (ex: GetPC, encodage, décodage), "
                "3) les syscalls ou fonctions Win32/Linux appelés et leur rôle, "
                "4) tout indicateur de compromission (IOC) visible (IP, URL, commandes), "
                "5) une conclusion sur la dangerosité et le type d'attaque probable."
            ),
            input=prompt,
        )

        return response.output_text