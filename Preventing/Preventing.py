# malware_detector_folder.py
import os
import re
from time import sleep
from load import start
import colorama

print("\n\n")
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
        b'\x0F\x01\xD0': 'VMCALL Instruction',
        b'\x55\x8B\xEC\x83\xEC\x08': 'Stack Frame Setup',
        b'\xE8\x00\x00\x00\x00': 'Call Instruction',
        b'\xEB\xFE': 'Jump Backward',
        b'\x33\xC0\xC3': 'XOR and RET',
        b'\xB8\xFF\xFF\xFF\x7F': 'Infinite Loop',
        b'\x8B\x45\x08\x89\x45\xF8': 'Stack Variable Manipulation',
        b'\x8D\x7D\xF4\x8B\x4D\xF8': 'Register Indirect Loading',
        b'\xBA\xAD\xDE\xEF\xFE': 'Magic Value',
        b'\xCC': 'Int3 Breakpoint',
        b'\x0F\x0B': 'UD2 Instruction',
        b'\x2E\x2E\x2E': 'Ellipsis',
        b'\x55\x55\x55\x55': 'Repeating Values',
        b'\x41\x41\x41\x41': 'Repeating ASCII Values',
        b'\xDE\xAD\xBE\xEF': 'Dead Beef',
        b'\xCA\xFE\xBA\xBE': 'Cafebabe',
        b'\xAA\xAA\xAA\xAA': 'Repeating AAAA',
        b'\xBB\xBB\xBB\xBB': 'Repeating BBBB',
        b'\xCC\xCC\xCC\xCC': 'Repeating CCCC',
        b'\xDD\xDD\xDD\xDD': 'Repeating DDDD',
        b'\xEE\xEE\xEE\xEE': 'Repeating EEEE',
        b'\xFF\xFF\xFF\xFF': 'Repeating FFFF',
        b'\x41\x42\x43\x44': 'ABCD',
        b'\x31\x32\x33\x34': '1234',
        b'\x78\x56\x34\x12': 'Little-endian Byte Order',
        b'\x12\x34\x56\x78': 'Big-endian Byte Order',
        b'\x4D\x5A': 'MZ Header (Executable)',
        b'\x50\x45\x00\x00': 'PE Signature',
        b'\x7F\x45\x4C\x46': 'ELF Header',
        b'\x25\x50\x44\x46': 'PDF Header',
        b'\x4F\x67\x67\x53': 'OGG Header',
        b'\x1F\x8B\x08': 'Gzip Header',
        b'\x42\x5A\x68': 'Bzip2 Header',
        b'\x37\x7A\xBC\xAF': '7z Header',
        b'\xFD\x37\x7A\x58\x5A\x00\x00': 'xz Header',
        b'\x30\x39\x0A': 'INI File Signature',
        b'\x2F\x2A': 'C Style Comment',
        b'\x3B': 'Semicolon (;) Comment',
        b'\x23': 'Hash (#) Comment',
        b'\x2F\x2F': 'Double Slash (//) Comment',
        b'\x2D\x2D': 'Double Dash (--) Comment',
        b'\x2D\x2D\x3E': 'Arrow (->) Sequence',
        b'\x2F\x2A\x20': 'C Style Comment with Space',
        b'\x21\x2F\x42\x49': 'Shebang (#!) Script Header',
        b'\xE9\x68\x32\xC7': 'JMP Instruction',
        b'\xE8\x4B\x3D\xE0\xFF': 'CALL Instruction',
        b'\xC3': 'RET Instruction',
        b'\xC2\x10\x00': 'RET Instruction with Pop',
        b'\xC9\xC3': 'LEAVE and RET Instructions',
        b'\xC9\xC2\x10\x00': 'LEAVE and RET Instructions with Pop',
        b'\xC9': 'LEAVE Instruction',
        b'\xF3\x0F\x1E\xFB': 'NOP Instruction',
        b'\xF4': 'HLT Instruction',
        b'\xCD\x20': 'INT 20h',
        b'\xCD\x21': 'INT 21h',
        b'\x0E': 'PUSH CS',
        b'\x1F': 'PUSH DS',
        b'\x07': 'POP ES',
        b'\x17': 'POP SS',
        b'\x9C': 'PUSHF',
        b'\x9D': 'POPF',
        b'\xFC': 'CLD',
        b'\xFD': 'STD',
        b'\xFA': 'CLI',
        b'\xFB': 'STI',
        b'\x66\x0F\x3A\x0F\xD5': 'AES-NI Instruction',
        b'\x0F\x01\xD0': 'VMCALL Instruction',
        b'\x0F\x01\xD1': 'VMLAUNCH Instruction',
        b'\x0F\x01\xD2': 'VMRESUME Instruction',
        b'\x0F\x01\xD4': 'VMXOFF Instruction',
        b'\x0F\x01\xD5': 'VMXON Instruction',
        b'\x0F\x3F\x0F': 'RDTSCP Instruction',
        b'\x0F\x05': 'SYSCALL Instruction',
        b'\x0F\x34': 'SYSENTER Instruction',
        b'\x0F\x35': 'SYSEXIT Instruction',
        b'\x0F\x22\xC0': 'PAUSE Instruction',
        b'\xC4\xE2\x79\x7D': 'VMP0 Algorithm',
        b'\xC4\xE2\x7A\x7D': 'VMP1 Algorithm',
        b'\xC4\xE2\x7B\x7D': 'VMP2 Algorithm',
        b'\xC4\xE2\x7C\x7D': 'VMP3 Algorithm',
        b'\xC4\xE2\x7D\x7D': 'VMP4 Algorithm',
        b'\xC4\xE2\x7E\x7D': 'VMP5 Algorithm',
        b'\xC4\xE2\x7F\x7D': 'VMP6 Algorithm',
        b'\xC4\xE2\x80\x7D': 'VMP7 Algorithm',
        b'\xC4\xE2\x81\x7D': 'VMP8 Algorithm',
        b'\xC4\xE2\x82\x7D': 'VMP9 Algorithm'

    }
    return signatures
global signature_type_list
signature_type_list = []
def analyze_file(file_path, signatures):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()

            
            for signature, signature_type in signatures.items():
                if signature in content:
                    signature_type_list.append(signature_type)

            if not signature_type_list:
                print(f"{colorama.Fore.RED}No malware signatures detected in {colorama.Fore.BLUE}{file_path}{colorama.Fore.RESET}")
    except FileNotFoundError:
        print(f"{colorama.Fore.RED}File not found: {colorama.Fore.BLUE}{file_path}{colorama.Fore.RESET}")

def analyze_folder(file_path, signatures):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()

            for signature, signature_type in signatures.items():
                match = re.search(re.escape(signature), content)
                if match:
                    start_offset = match.start()
                    end_offset = match.end()
                    located_signature = content[start_offset:end_offset].hex()
                    print(f"\n{colorama.Fore.RED}Malware Signature Detected in :{colorama.Fore.BLUE} {file_path}{colorama.Fore.RESET}")
                    print(f"{colorama.Fore.RED}Signature Type:{colorama.Fore.BLUE} {signature_type}{colorama.Fore.RESET}")
                    print(f"{colorama.Fore.RED}Start Offset:{colorama.Fore.BLUE} {colorama.Fore.RED}{start_offset}, End Offset: {colorama.Fore.BLUE}{end_offset}{colorama.Fore.RESET}")
                    print(f"{colorama.Fore.RED}Located Signature: {colorama.Fore.BLUE} {located_signature}{colorama.Fore.RESET}\n")
    except FileNotFoundError:
        print(f"{colorama.Fore.RED}File not found: {colorama.Fore.BLUE}{file_path}{colorama.Fore.RESET}")

def detect_malware_in_folder(folder_path):
    signatures = load_signatures()

    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            analyze_folder(file_path, signatures)

if __name__ == "__main__":
    print("\n\n")
    print(colorama.Fore.RED)
    print("Do you want to Prevent a file or a folder?")
    print(colorama.Fore.BLUE)
    print("1. File \n2. Folder \n")
    print(colorama.Fore.RED)
    choice = int(input("Enter your choice: "))
    print(colorama.Fore.RESET)
    print("\n\n")
    if choice == 1:
        print(colorama.Fore.RED)
        file_path = input("Enter the file path to scan: ")
        print("\n\n")
        print(colorama.Fore.RESET)
        analyze_file(file_path, load_signatures())    
    elif choice == 2:
        print(colorama.Fore.RED)
        folder_path = input("Enter the folder path to scan: ")
        print("\n\n")
        print(colorama.Fore.RESET)
        detect_malware_in_folder(folder_path)
    else:
        print(colorama.Fore.RED)
        print("Invalid choice")
        print(colorama.Fore.RESET)

# Clean and organize the signature_type_list
signature_type_list = list(set(signature_type_list))

# Define malware signature definitions
definitions_dict = {
    "NOP Sled": "A series of NOP (No Operation) instructions used as a placeholder or for padding.",
    "Metasploit Payload": "A piece of code generated by the Metasploit Framework to exploit vulnerabilities.",
    "Stack Frame Setup": "The preparation of the stack for a function call, including saving registers and local variables.",
    "Call Instruction": "An instruction that transfers control to a subroutine or function.",
    "Jump Backward": "An instruction that causes the program to jump backward to a previous point in the code.",
    "XOR and RET": "A technique that uses XOR operations to obfuscate a return address on the stack.",
    "Infinite Loop": "A loop that repeats indefinitely, often used for waiting or polling.",
    "Int3 Breakpoint": "An interrupt instruction (INT3) used for debugging purposes to pause program execution.",
    "JMP Instruction": "An unconditional jump instruction that transfers control to a specified address.",
    "CALL Instruction": "An instruction used to call a subroutine or function.",
    "RET Instruction": "An instruction that returns control from a subroutine to the calling function.",
    "VMCALL Instruction": "An instruction used in virtualization to make hypercalls to the virtual machine monitor."
}

# Loop to check if list elements are present in the dictionary
for element in signature_type_list:
    if element in definitions_dict:
        print(f"{colorama.Fore.RED}{element}  :{colorama.Fore.RESET}\n")
        print(f"{colorama.Fore.BLUE}{definitions_dict[element]}{colorama.Fore.RESET}\n\n")
