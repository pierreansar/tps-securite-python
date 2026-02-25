import os
import sys

from tp2.utils.config import logger
from tp2.utils.shell_code_analyzer import ShellCodeAnalyzer

if __name__ == "__main__":
    logger.info(f"Key openai value : {os.getenv('OPENAI_API_KEY')}")

    # Shellcode en hex : priorité à l'arg CLI, puis à la variable d'env SHELLCODE
    if len(sys.argv) > 1:
        shellcode_hex = sys.argv[1]
    elif os.getenv("SHELLCODE"):
        shellcode_hex = os.getenv("SHELLCODE")
    else:
        shellcode_hex = input("Entrez le shellcode à analyser (en hexadécimal) : ")
    shellcode_bytes = bytes.fromhex(shellcode_hex)

    analyzer = ShellCodeAnalyzer(shellcode_bytes)

    print("Extraction des strings du shellcode")
    strings = analyzer.get_shellcode_strings()
    print("Strings extraites :")
    for s in strings:
        print(f"  {s}")

    print("Analyse avec pylibemu...")
    pylibemu_result = analyzer.get_pylibemu_analysis()
    print(pylibemu_result)

    print("Analyse avec Capstone...")
    capstone_result = analyzer.get_capstone_analysis()
    print(capstone_result)

    print("Analyse avec LLM, retourne un rapport complet sur ce que fait le shellcode...")
    llm_result = analyzer.get_llm_analysis()
    print(llm_result)