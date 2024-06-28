Simple tool to convert an ESP8266 bin file into an bare-bones ELF file.
The intended typical workflow:
- Read a .bin file from the ESP8266 Flash memory
- Use esp8266-bin2elf to convert it to ELF file(s)
- Examine the ELF files using a tool such as Ghidra.

Usage:

    python esp8266-bin2elf.py yourfile.bin
