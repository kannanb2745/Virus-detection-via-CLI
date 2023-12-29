# malware_detector_folder.py
import os
import re
from time import sleep
from load import start
import colorama


print(colorama.Fore.BLUE)
print("**************************************************************************************")
print("**************************************************************************************")
print("**                                                                                  **")
print("**                                                                                  **")
print("**     **********  **********  **********  **********  ***    ***      *********    **")
print("**     ***    ***  **********  **********  **********  ***    ***      *********    **")
print("**     ***    ***  ***    ***     ****     ***         ***    ***            ***    **")
print("**     **********  ***    ***     ****     ***         **********  ****      ***    **")
print("**     **********  **********     ****     ***         **********  ****      ***    **")
print("**     ***    ***  **********     ****     ***         ***    ***            ***    **")
print("**     ***    ***  ***    ***     ****     **********  ***    ***            ***    **")
print("**     **********  ***    ***     ****     **********  ***    ***            ***    **")
print("**                                                                                  **")
print("**             KANNAN   B                                                           **")
print("**                             KRISHNA KUMAR    E                                   **")
print("**                                                      MADHAVAN  M                 **")
print("**                                                                                  **")
print("**         Disclaimer: The code shared is for educational purposes only             **")
print("**         Use it responsibly, and we are not liable for any consequences           **")
print("**         resulting from its application in real-world scenarios.                  **")
print("**                                                                                  **")
print("**************************************************************************************")
print("**************************************************************************************")
print(colorama.Fore.RESET)

sleep(3)




def load_signatures():
    # Example signatures (modify or expand based on actual signatures)
    signatures = {
        b'\x90\x90\x90\x90': 'NOP Sled',
        b'\xD9\xEE\xD9\x74\x24\xF4\x59': 'Metasploit Payload',
        b'\x55\x8B\xEC\x83\xEC\x08': 'Stack Frame Setup',
        b'\xE8\x00\x00\x00\x00': 'Call Instruction',
        b'\xEB\xFE': 'Jump Backward',
        b'\x33\xC0\xC3': 'XOR and RET',
        b'\xB8\xFF\xFF\xFF\x7F': 'Infinite Loop',
        b'\xCC': 'Int3 Breakpoint',
        b'\xE9\x68\x32\xC7': 'JMP Instruction',
        b'\xE8\x4B\x3D\xE0\xFF': 'CALL Instruction',
        b'\xC3': 'RET Instruction',
        b'\x0F\x01\xD0': 'VMCALL Instruction'
    }
    return signatures

def analyze_file(file_path, signatures):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()

            for signature, signature_type in signatures.items():
                match = re.search(re.escape(signature), content)
                if match:
                    start_offset = match.start()
                    end_offset = match.end()
                    located_signature = content[start_offset:end_offset].hex()
                    print(f"\nMalware Signature Detected in {file_path}: {signature_type}")
                    print(f"Signature Type: {signature_type}")
                    print(f"Start Offset: {start_offset}, End Offset: {end_offset}")
                    print(f"Located Signature: {located_signature}\n")
    except FileNotFoundError:
        print(f"File not found: {file_path}")

def detect_malware_in_folder(folder_path):
    signatures = load_signatures()

    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            analyze_file(file_path, signatures)

if __name__ == "__main__":
    print("\n\n")
    folder_path = input("Enter the folder path: ")
    print("\n")
    start("DETECTING")
    sleep(2)
    detect_malware_in_folder(folder_path)
print(f"\n\n{colorama.Fore.RED}THESE ARE THE MALWARE FIND IN YOUR FOLDER PATH{colorama.Fore.RESET}")
