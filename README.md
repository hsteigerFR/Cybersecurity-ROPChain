# Cybersecurity - ROP Chain

This project was carried out as part as Mines Nancy last year "Information Systems Attacks" course, within the Computer Science Departement. The projet goal was to create a ROP Chain exploit with a chosen program, on a recent version of Windows. CVE-2018-6892, refering to a CloudMe vulnerability (v1.11.2), was used to make the exploit.

The exploit strategy is illustrated below. First, open CloudMe_1112.exe. Once launched with Python 2.7, ROPChain.py will send a message to the local 8888 port that CloudMe is listening to. Because of the vulnerability, one part of this message, starting from the 1053th byte, will be interpreted by Windows : the ROP Chain will setup VirtualProtect() then execute the shellcode, opening calc.exe.

![Strategy](https://user-images.githubusercontent.com/106969232/179573234-0d148565-c131-4426-8d1d-9824c23e8ad4.JPG)

The ROP Chain was built using gadgets from different available libraries, retrieved thanks to mona.py and Immunity Debugger. A gadget executes a series of instruction, then returns and points to the next link in the chain. Here is the succession of instructions to setup VirtualProtect() correctly (with the proper register values) :

![ROPChain Explained](https://user-images.githubusercontent.com/106969232/179573210-d15caf31-53d3-40df-8ca5-2c27ffe473cd.JPG)

