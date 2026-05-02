# PE Format Notes

## What is a PE file?

Portable Executable (PE) is the binary format Windows uses for `.exe`, `.dll`, `.sys`, and `.ocx` files.
A loader (Wine, Windows kernel, or our toy loader) must parse this format to run the program.

## File layout (top to bottom)

```
[DOS Header]         ← legacy, contains MZ magic + offset to PE header
[DOS Stub]           ← tiny "This program cannot be run in DOS mode" program
[PE Signature]       ← "PE\0\0" magic
[File Header]        ← machine type, section count, timestamp
[Optional Header]    ← entry point, image base, section alignment, subsystem
[Section Table]      ← array of section descriptors
[Sections]           ← .text (code), .data, .rdata, .idata (imports), .reloc, etc.
```

## Key fields

| Field | Where | Meaning |
|---|---|---|
| `Machine` | File Header | Target CPU: 0x8664=x64, 0x014C=x86 |
| `AddressOfEntryPoint` | Optional Header | RVA where execution begins |
| `ImageBase` | Optional Header | Preferred load address (0x400000 for EXEs) |
| `Magic` | Optional Header | 0x10B=PE32, 0x20B=PE32+ (64-bit) |
| `Subsystem` | Optional Header | 2=GUI, 3=Console, 1=Native driver |
| `NumberOfSections` | File Header | How many sections follow |

## Sections

| Section | Purpose |
|---|---|
| `.text` | Executable code |
| `.data` | Initialized global/static variables |
| `.bss` | Uninitialized data (zero-filled at load time) |
| `.rdata` | Read-only data: strings, constants |
| `.idata` | Import table: which DLLs and functions are needed |
| `.edata` | Export table: functions this DLL exposes |
| `.reloc` | Relocation table: patches if not loaded at ImageBase |
| `.rsrc` | Resources: icons, manifests, version info |

## Section characteristics flags (key ones)

| Flag | Hex | Meaning |
|---|---|---|
| `IMAGE_SCN_CNT_CODE` | 0x20 | Contains executable code |
| `IMAGE_SCN_CNT_INITIALIZED_DATA` | 0x40 | Contains initialized data |
| `IMAGE_SCN_CNT_UNINITIALIZED_DATA` | 0x80 | Contains uninitialized data |
| `IMAGE_SCN_MEM_EXECUTE` | 0x20000000 | Memory is executable |
| `IMAGE_SCN_MEM_READ` | 0x40000000 | Memory is readable |
| `IMAGE_SCN_MEM_WRITE` | 0x80000000 | Memory is writable |

## Import table (.idata)

Lists every DLL the program needs and every function it calls from that DLL.
This is what a loader must resolve before the program can run.

Example from `nmap_service.exe`:
- `KERNEL32.dll` → `CreateProcessA`, `LoadLibraryA`, `GetProcAddress`, ...
- `ADVAPI32.dll` → `StartServiceCtrlDispatcherA`, `SetServiceStatus`, ...
- `msvcrt.dll` → C runtime functions

Wine's job: provide Linux implementations of all these functions.

## RVA vs VA vs File Offset

- **RVA** (Relative Virtual Address): offset from `ImageBase` in memory
- **VA** (Virtual Address): `ImageBase + RVA`  
- **File Offset**: physical position in the `.exe` file on disk

The loader maps file data into memory, aligning sections to page boundaries (usually 0x1000).

## What the loader must do (simplified)

1. Read DOS header → find PE offset
2. Validate `PE\0\0` signature
3. Read File Header + Optional Header
4. Allocate memory at `ImageBase` (or wherever available)
5. Map each section: read raw bytes from file → write to `VirtualAddress` in memory
6. Process `.reloc` if loaded at a different address than `ImageBase`
7. Resolve imports: for each DLL + function, find the address and write it into the IAT
8. Jump to `AddressOfEntryPoint`

## Tools for exploring PE files

```bash
python3 tools/pe_inspector.py samples/nmap_service.exe   # this project
objdump -x samples/nmap_service.exe                      # GNU binutils
readelf -a samples/nmap_service.exe                      # ELF/PE headers
file samples/nmap_service.exe                            # quick type check
hexdump -C samples/nmap_service.exe | head -4            # raw bytes (should see MZ)
```
