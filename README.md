# ntoskrnl-offsets-dumper

Dump Windows kernel offsets from ntoskrnl.exe using Radare2.  
Works on Windows 10 and Windows 11. Needs Radare2 installed.

## what it does

- Grabs offsets for useful kernel structures (EPROCESS, ETHREAD, KTHREAD, KPCR, etc.)
- Can dump everything with `--all` (every function, variable, struct from the PDB)
- Outputs as plain text or JSON
- Supports custom ntoskrnl.exe path and custom PDB file

## requirements

- Rust (to compile)
- Radare2 >= 5.0.0 (install from https://github.com/radareorg/radare2/releases)

## how to build

```cmd
cargo build --release
```
The exe will be in target\release\ntoskrnl-offsets.exe

usage examples for every mode
default mode (63 known offsets)
```cmd
cargo run
```
json output (default offsets)
```cmd
cargo run -- --json
```
dump every single symbol (raw radare2 output)
```cmd
cargo run -- --all
```
dump every symbol as json
```cmd
cargo run -- --all --json > all_symbols.json
```
custom ntoskrnl.exe path
```cmd
cargo run -- --ntoskrnl D:\ntoskrnl_old.exe
```
custom ntoskrnl.exe with json
```cmd
cargo run -- --ntoskrnl D:\ntoskrnl_old.exe --json
```
custom pdb file (skip download)
```cmd
cargo run -- --pdb C:\symbols\ntkrnlmp.pdb
```
custom pdb with json
```cmd
cargo run -- --pdb C:\symbols\ntkrnlmp.pdb --json
```
verbose mode (see radare2 output)
```cmd
cargo run -- --verbose
```
verbose with all symbols
```cmd
cargo run -- --all --verbose
```
## notes
The default list has 63 offsets. Some may be missing on your Windows version because Microsoft changes struct layouts.

--all gives you everything radare2's idpi command outputs. That includes function names, global variables, type info, etc.

Radare2 will try to download the PDB automatically. If that fails, use --pdb with a manually downloaded PDB (via symchk or WinDbg).

Works on both Windows 10 and Windows 11 (tested on 22H2 and later).

## credits
vtorres (for original project) -> https://github.com/vtorres/ntoskrnl-offsets-dumper

## showcase (Windows 10 22H2 (OS Build 19045.6466)
https://github.com/user-attachments/assets/6b49badb-c844-447a-b2b3-c6a2b5d142ec
