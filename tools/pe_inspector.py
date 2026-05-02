#!/usr/bin/env python3
"""
WoadyCompat PE Inspector — Phase 1
Static analysis tool: reads and prints Windows PE binary metadata.

Safety boundaries:
  - Static analysis only.  The input file is never executed.
  - No executable memory allocation.
  - No DLL loading, process injection, or shellcode.
  - Uses only Python standard library.
"""

import argparse
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Constants derived from the PE specification
# ---------------------------------------------------------------------------

MACHINE_TYPES = {
    0x0000: "Unknown",
    0x014C: "x86 (i386)",
    0x0200: "IA-64 (Itanium)",
    0x8664: "x86-64 (AMD64)",
    0xAA64: "ARM64",
    0x01C4: "ARM (Thumb-2)",
    0x01C0: "ARM (little-endian)",
    0x0EBC: "EFI Bytecode",
}

SUBSYSTEMS = {
    0:  "Unknown",
    1:  "Native",
    2:  "Windows GUI",
    3:  "Windows Console (CUI)",
    5:  "OS/2 Console",
    7:  "POSIX Console",
    9:  "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

SECTION_FLAGS = [
    (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_IDATA"),
    (0x00000080, "CNT_UDATA"),
    (0x00000200, "LNK_INFO"),
    (0x02000000, "MEM_DISCARDABLE"),
    (0x04000000, "MEM_NOT_CACHED"),
    (0x08000000, "MEM_NOT_PAGED"),
    (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
]


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def read_u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]

def read_u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def read_u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]

def section_flags_str(chars):
    active = [name for mask, name in SECTION_FLAGS if chars & mask]
    return " | ".join(active) if active else "-"

def divider(char="-", width=60):
    print(char * width)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def inspect(path):
    # --- File read ---
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    file_size = len(data)

    divider("=")
    print(f"  WoadyCompat PE Inspector")
    divider("=")
    print(f"  File : {os.path.basename(path)}")
    print(f"  Path : {os.path.abspath(path)}")
    print(f"  Size : {file_size:,} bytes ({file_size:#010x})")

    # --- DOS header ---
    divider()
    print("  DOS HEADER")
    divider()

    if file_size < 64:
        print("  ERROR: File too small to contain a DOS header.")
        sys.exit(1)

    mz = data[0:2]
    mz_valid = mz == b"MZ"
    print(f"  Magic (e_magic)  : {mz!r}  {'[VALID]' if mz_valid else '[INVALID — not a PE file]'}")

    if not mz_valid:
        sys.exit(1)

    e_lfanew = read_u32(data, 0x3C)
    print(f"  PE offset (e_lfanew) : {e_lfanew:#010x}  (decimal {e_lfanew})")

    # --- PE signature ---
    divider()
    print("  PE SIGNATURE")
    divider()

    if e_lfanew + 4 > file_size:
        print("  ERROR: e_lfanew points outside the file.")
        sys.exit(1)

    pe_sig = data[e_lfanew : e_lfanew + 4]
    pe_valid = pe_sig == b"PE\x00\x00"
    print(f"  Signature : {pe_sig!r}  {'[VALID]' if pe_valid else '[INVALID]'}")

    if not pe_valid:
        sys.exit(1)

    # --- COFF / File header (20 bytes after the PE signature) ---
    coff_offset = e_lfanew + 4
    if coff_offset + 20 > file_size:
        print("  ERROR: File too small for COFF header.")
        sys.exit(1)

    machine         = read_u16(data, coff_offset + 0)
    num_sections    = read_u16(data, coff_offset + 2)
    timestamp       = read_u32(data, coff_offset + 4)
    opt_hdr_size    = read_u16(data, coff_offset + 16)
    characteristics = read_u16(data, coff_offset + 18)

    divider()
    print("  COFF / FILE HEADER")
    divider()
    print(f"  Machine           : {machine:#06x}  ({MACHINE_TYPES.get(machine, 'Unknown')})")
    print(f"  Number of sections: {num_sections}")
    print(f"  Timestamp         : {timestamp:#010x}  (raw, seconds since 1970-01-01)")
    print(f"  Opt header size   : {opt_hdr_size} bytes")
    print(f"  Characteristics   : {characteristics:#06x}")

    is_dll = bool(characteristics & 0x2000)
    is_exe = bool(characteristics & 0x0002)
    print(f"  File type         : {'DLL' if is_dll else 'EXE' if is_exe else 'other'}")

    # --- Optional header ---
    opt_offset = coff_offset + 20
    if opt_hdr_size == 0 or opt_offset + opt_hdr_size > file_size:
        print("\n  (No optional header or header exceeds file bounds.)")
        return

    opt_magic = read_u16(data, opt_offset)
    is_pe32plus = opt_magic == 0x020B
    is_pe32     = opt_magic == 0x010B

    divider()
    print("  OPTIONAL HEADER")
    divider()
    print(f"  Magic      : {opt_magic:#06x}  ({'PE32+' if is_pe32plus else 'PE32' if is_pe32 else 'unknown'})")

    if not (is_pe32 or is_pe32plus):
        print("  WARNING: Unrecognised optional header magic.")
        return

    entry_point = read_u32(data, opt_offset + 16)
    print(f"  Entry point RVA   : {entry_point:#010x}")

    if is_pe32:
        image_base = read_u32(data, opt_offset + 28)
        subsystem  = read_u16(data, opt_offset + 68)
    else:  # PE32+
        image_base = read_u64(data, opt_offset + 24)
        subsystem  = read_u16(data, opt_offset + 68)

    print(f"  Image base        : {image_base:#018x}")
    print(f"  Subsystem         : {subsystem}  ({SUBSYSTEMS.get(subsystem, 'Unknown')})")

    # --- Section table ---
    # Starts immediately after the optional header
    section_table_offset = opt_offset + opt_hdr_size

    divider()
    print(f"  SECTION TABLE  ({num_sections} sections)")
    divider()

    # Header row
    print(f"  {'Name':<10} {'VirtAddr':>12} {'VirtSize':>12} {'RawPtr':>12} {'RawSize':>10}  Characteristics")
    divider("-", 80)

    SECTION_HDR_SIZE = 40
    for i in range(num_sections):
        sec_off = section_table_offset + i * SECTION_HDR_SIZE
        if sec_off + SECTION_HDR_SIZE > file_size:
            print(f"  Section {i}: offset {sec_off:#x} exceeds file — truncated binary?")
            break

        raw_name    = data[sec_off : sec_off + 8]
        name        = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")
        virt_size   = read_u32(data, sec_off + 8)
        virt_addr   = read_u32(data, sec_off + 12)
        raw_size    = read_u32(data, sec_off + 16)
        raw_ptr     = read_u32(data, sec_off + 20)
        chars       = read_u32(data, sec_off + 36)

        flags_str = section_flags_str(chars)
        print(f"  {name:<10} {virt_addr:#012x} {virt_size:#012x} {raw_ptr:#012x} {raw_size:>10}  {flags_str}")

    divider("=")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="WoadyCompat PE Inspector: static analysis of Windows PE binaries.",
        epilog="Safety: this tool performs read-only static analysis. "
               "The input file is never executed.",
    )
    parser.add_argument(
        "file",
        metavar="FILE",
        help="Path to a Windows PE binary (.exe, .dll, .sys, ...)",
    )
    args = parser.parse_args()
    inspect(args.file)


if __name__ == "__main__":
    main()
