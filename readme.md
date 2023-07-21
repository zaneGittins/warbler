# Warbler

A minidump analysis tool built with blue teams in mind. Supports running Yara rules against virtual addresses and dumping virtual memory to disk.

## Usage

[![asciicast](https://asciinema.org/a/JEPLgiH1IHgSQbnk6MSIJFWLZ.svg)](https://asciinema.org/a/JEPLgiH1IHgSQbnk6MSIJFWLZ)

View threads:
```bash
./warbler --file ~/Desktop/mem/RuntimeBroker.exe.dmp threads
```

View loaded and unloaded modules:
```bash
./warbler --file ~/Desktop/mem/RuntimeBroker.exe.dmp modules
```

View memory:
```bash
./warbler --file ~/Desktop/mem/RuntimeBroker.exe.dmp memory
```

Run yara rules against virtual address:
```bash
./warbler --file ~/Desktop/mem/RuntimeBroker.exe.dmp yara --rules /opt/yara/ --address 0x2879d9c0000
```

Dump to disk:
```bash
./warbler --file ~/Desktop/mem/RuntimeBroker.exe.dmp dump --address 0x2879d9c0000 --out shellcode.bin
```