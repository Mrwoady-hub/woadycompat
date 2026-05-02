#!/usr/bin/env python3
"""
WoadyCompat PE Mapper — Phase 3
Models how a loader reasons about a PE binary: virtual memory layout,
section mapping, and import table resolution — without executing the file.

Safety boundaries:
  - Static analysis only.  The input file is never executed.
  - No executable memory allocation (mmap with PROT_EXEC, ctypes, etc.).
  - No DLL loading, process injection, or shellcode.
  - Uses only Python standard library.
"""

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data structures — mirror the PE spec in plain Python
# ---------------------------------------------------------------------------

@dataclass
class DosHeader:
    e_magic: bytes      # b"MZ"
    e_lfanew: int       # file offset of PE signature


@dataclass
class CoffHeader:
    machine: int
    num_sections: int
    timestamp: int
    opt_header_size: int
    characteristics: int


@dataclass
class OptionalHeader:
    magic: int          # 0x10B = PE32, 0x20B = PE32+
    entry_point_rva: int
    image_base: int
    section_alignment: int   # alignment of sections in memory
    file_alignment: int      # alignment of raw data in file
    image_size: int
    subsystem: int


@dataclass
class Section:
    name: str
    virtual_address: int    # RVA — relative to image base
    virtual_size: int       # size in memory (may be larger than raw size)
    raw_ptr: int            # file offset of raw data
    raw_size: int           # size in file
    characteristics: int

    def rva_to_file_offset(self, rva: int) -> Optional[int]:
        """Convert an RVA inside this section to a file offset."""
        if self.virtual_address <= rva < self.virtual_address + self.virtual_size:
            return self.raw_ptr + (rva - self.virtual_address)
        return None

    def flag_str(self) -> str:
        flags = [
            (0x20,       "CODE"),
            (0x40,       "IDATA"),
            (0x80,       "UDATA"),
            (0x20000000, "EXEC"),
            (0x40000000, "READ"),
            (0x80000000, "WRITE"),
        ]
        return " | ".join(name for mask, name in flags if self.characteristics & mask) or "-"


@dataclass
class ImportedFunction:
    name: Optional[str]     # None if imported by ordinal
    ordinal: Optional[int]


@dataclass
class ImportDescriptor:
    dll_name: str
    functions: List[ImportedFunction] = field(default_factory=list)


@dataclass
class PEImage:
    path: str
    file_size: int
    dos: DosHeader
    coff: CoffHeader
    opt: OptionalHeader
    sections: List[Section] = field(default_factory=list)
    imports: List[ImportDescriptor] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Low-level reads
# ---------------------------------------------------------------------------

def u16(data, off): return struct.unpack_from("<H", data, off)[0]
def u32(data, off): return struct.unpack_from("<I", data, off)[0]
def u64(data, off): return struct.unpack_from("<Q", data, off)[0]

def cstr(data, off) -> str:
    """Read a null-terminated ASCII string from a file offset."""
    end = data.index(b"\x00", off)
    return data[off:end].decode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# RVA resolution across the section table
# ---------------------------------------------------------------------------

def rva_to_offset(sections: List[Section], rva: int) -> Optional[int]:
    for sec in sections:
        off = sec.rva_to_file_offset(rva)
        if off is not None:
            return off
    return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse(path: str) -> PEImage:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if len(data) < 64 or data[:2] != b"MZ":
        print("Error: not a valid PE file (missing MZ magic).", file=sys.stderr)
        sys.exit(1)

    e_lfanew = u32(data, 0x3C)
    dos = DosHeader(e_magic=data[:2], e_lfanew=e_lfanew)

    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        print("Error: PE signature not found.", file=sys.stderr)
        sys.exit(1)

    coff_off = e_lfanew + 4
    coff = CoffHeader(
        machine         = u16(data, coff_off),
        num_sections    = u16(data, coff_off + 2),
        timestamp       = u32(data, coff_off + 4),
        opt_header_size = u16(data, coff_off + 16),
        characteristics = u16(data, coff_off + 18),
    )

    opt_off   = coff_off + 20
    opt_magic = u16(data, opt_off)
    is_plus   = opt_magic == 0x020B

    if is_plus:
        image_base       = u64(data, opt_off + 24)
        sec_alignment    = u32(data, opt_off + 32)
        file_alignment   = u32(data, opt_off + 36)
        image_size       = u32(data, opt_off + 56)
        subsystem        = u16(data, opt_off + 68)
    else:
        image_base       = u32(data, opt_off + 28)
        sec_alignment    = u32(data, opt_off + 32)
        file_alignment   = u32(data, opt_off + 36)
        image_size       = u32(data, opt_off + 56)
        subsystem        = u16(data, opt_off + 68)

    opt = OptionalHeader(
        magic            = opt_magic,
        entry_point_rva  = u32(data, opt_off + 16),
        image_base       = image_base,
        section_alignment= sec_alignment,
        file_alignment   = file_alignment,
        image_size       = image_size,
        subsystem        = subsystem,
    )

    # Sections
    sec_table_off = opt_off + coff.opt_header_size
    sections: List[Section] = []
    for i in range(coff.num_sections):
        off = sec_table_off + i * 40
        name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        sections.append(Section(
            name             = name,
            virtual_size     = u32(data, off + 8),
            virtual_address  = u32(data, off + 12),
            raw_size         = u32(data, off + 16),
            raw_ptr          = u32(data, off + 20),
            characteristics  = u32(data, off + 36),
        ))

    # Import table — walk IMAGE_IMPORT_DESCRIPTOR array
    # Data directory entry 1 (imports) is at opt_off + 104 (PE32) or opt_off + 120 (PE32+)
    import_dir_rva_off = opt_off + (120 if is_plus else 104)
    imports: List[ImportDescriptor] = []

    if import_dir_rva_off + 8 <= len(data):
        import_rva  = u32(data, import_dir_rva_off)
        import_size = u32(data, import_dir_rva_off + 4)

        if import_rva and import_size:
            desc_off = rva_to_offset(sections, import_rva)

            if desc_off is not None:
                # Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes; ends at an all-zero entry
                while desc_off + 20 <= len(data):
                    orig_thunk = u32(data, desc_off)
                    name_rva   = u32(data, desc_off + 12)
                    iat_rva    = u32(data, desc_off + 16)

                    # All-zero descriptor marks end of table
                    if orig_thunk == 0 and name_rva == 0 and iat_rva == 0:
                        break

                    dll_name_off = rva_to_offset(sections, name_rva)
                    dll_name = cstr(data, dll_name_off) if dll_name_off else "<unresolved>"

                    descriptor = ImportDescriptor(dll_name=dll_name)

                    # Walk the INT (import name table) for function names
                    thunk_rva = orig_thunk if orig_thunk else iat_rva
                    thunk_off = rva_to_offset(sections, thunk_rva)

                    if thunk_off is not None:
                        entry_size = 8 if is_plus else 4
                        ordinal_flag = (1 << 63) if is_plus else (1 << 31)

                        while thunk_off + entry_size <= len(data):
                            entry = (u64(data, thunk_off) if is_plus
                                     else u32(data, thunk_off))
                            if entry == 0:
                                break

                            if entry & ordinal_flag:
                                descriptor.functions.append(
                                    ImportedFunction(name=None, ordinal=entry & 0xFFFF)
                                )
                            else:
                                hint_rva = int(entry & 0x7FFFFFFF)
                                hint_off = rva_to_offset(sections, hint_rva)
                                if hint_off is not None and hint_off + 2 < len(data):
                                    # 2-byte hint, then null-terminated name
                                    fn_name = cstr(data, hint_off + 2)
                                    descriptor.functions.append(
                                        ImportedFunction(name=fn_name, ordinal=None)
                                    )

                            thunk_off += entry_size

                    imports.append(descriptor)
                    desc_off += 20

    return PEImage(
        path      = path,
        file_size = len(data),
        dos       = dos,
        coff      = coff,
        opt       = opt,
        sections  = sections,
        imports   = imports,
    )


# ---------------------------------------------------------------------------
# Loader walkthrough — educational output
# ---------------------------------------------------------------------------

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0xAA64: "ARM64",
}
SUBSYSTEM_NAMES = {
    1: "Native", 2: "GUI", 3: "Console", 9: "WinCE", 10: "EFI",
}

def div(char="-", w=72): print(char * w)

def report(img: PEImage):
    is_plus = img.opt.magic == 0x020B
    is_dll  = bool(img.coff.characteristics & 0x2000)

    div("=")
    print("  WoadyCompat PE Mapper — loader reasoning walkthrough")
    div("=")
    print(f"  File   : {os.path.basename(img.path)}")
    print(f"  Size   : {img.file_size:,} bytes")
    print(f"  Format : {'PE32+' if is_plus else 'PE32'}  "
          f"({'DLL' if is_dll else 'EXE'})  "
          f"{MACHINE_NAMES.get(img.coff.machine, hex(img.coff.machine))}")

    # ------------------------------------------------------------------
    print()
    div()
    print("  STEP 1 — Verify the file is a PE binary")
    div()
    print(f"  Loader reads offset 0 → MZ magic    : {img.dos.e_magic!r}  ✓")
    print(f"  Loader reads offset 0x3C → e_lfanew : {img.dos.e_lfanew:#x}")
    print(f"  Loader reads [{img.dos.e_lfanew:#x}] → PE sig      : b'PE\\x00\\x00'  ✓")
    print()
    print("  WHY: Before doing anything else a loader confirms these two magic")
    print("  values.  If either is wrong the file is rejected immediately.")

    # ------------------------------------------------------------------
    print()
    div()
    print("  STEP 2 — Reserve virtual address space")
    div()
    print(f"  Preferred image base : {img.opt.image_base:#018x}")
    print(f"  Total image size     : {img.opt.image_size:#010x}  ({img.opt.image_size:,} bytes)")
    print(f"  Section alignment    : {img.opt.section_alignment:#010x}  (in memory, usually 0x1000 = 4 KB page)")
    print(f"  File alignment       : {img.opt.file_alignment:#010x}  (in the .exe file on disk)")
    print()
    print("  WHY: The loader calls VirtualAlloc (Windows) / mmap (Linux Wine)")
    print(f"  to reserve {img.opt.image_size:,} bytes starting at the image base.")
    print("  If that address is already taken, relocation kicks in (see .reloc).")

    # ------------------------------------------------------------------
    print()
    div()
    print("  STEP 3 — Map sections from file into virtual memory")
    div()
    print(f"  {'Section':<10} {'File offset':>14} {'File size':>10}  →  "
          f"{'VA (base + RVA)':>22}  {'Mem size':>10}  Permissions")
    div("-", 88)

    for sec in img.sections:
        va = img.opt.image_base + sec.virtual_address
        perms = []
        if sec.characteristics & 0x20000000: perms.append("X")
        if sec.characteristics & 0x40000000: perms.append("R")
        if sec.characteristics & 0x80000000: perms.append("W")
        perm_str = "/".join(perms) if perms else "-"

        print(f"  {sec.name:<10} {sec.raw_ptr:#014x} {sec.raw_size:>10}  →  "
              f"{va:#022x}  {sec.virtual_size:>10}  {perm_str}")

    print()
    print("  WHY: Each section gets mapped to its virtual address. The loader")
    print("  copies raw bytes from file → memory, then zero-fills if virtual_size")
    print("  > raw_size (common for .bss which has no raw data at all).")
    print("  Permissions (R/W/X) come from section Characteristics — the loader")
    print("  calls mprotect / VirtualProtect to enforce them.")

    # ------------------------------------------------------------------
    print()
    div()
    print("  STEP 4 — Resolve imports (the hardest loader job)")
    div()

    if not img.imports:
        print("  No import table found.")
    else:
        total_fns = sum(len(d.functions) for d in img.imports)
        print(f"  {len(img.imports)} DLL(s) required, {total_fns} function(s) to resolve.")
        print()

        for desc in img.imports:
            print(f"  ┌ {desc.dll_name}  ({len(desc.functions)} imports)")
            for fn in desc.functions[:12]:
                if fn.name:
                    print(f"  │   {fn.name}")
                else:
                    print(f"  │   ordinal #{fn.ordinal}")
            if len(desc.functions) > 12:
                print(f"  │   ... and {len(desc.functions) - 12} more")
            print(f"  └─ Wine must provide all of these from its own DLL implementations.")
            print()

        print("  WHY: Before the entry point runs, the loader walks the IAT")
        print("  (Import Address Table).  For each DLL it loads the library and")
        print("  looks up every function by name or ordinal.  It writes the real")
        print("  function address into the IAT slot so that when the program calls")
        print("  e.g. KERNEL32.CreateProcessA it jumps to the correct address.")
        print()
        print("  Wine's job: provide its own kernel32.dll, user32.dll, etc. that")
        print("  implement these functions using Linux syscalls underneath.")

    # ------------------------------------------------------------------
    print()
    div()
    print("  STEP 5 — Apply relocations (if base address changed)")
    div()
    has_reloc = any(s.name == ".reloc" for s in img.sections)
    stripped  = bool(img.coff.characteristics & 0x0001)
    print(f"  .reloc section present : {'yes' if has_reloc else 'no'}")
    print(f"  Relocations stripped   : {'yes' if stripped else 'no'}")
    print()
    print("  WHY: If the image was not loaded at its preferred image base,")
    print("  every absolute address embedded in the code is wrong.  The .reloc")
    print("  section lists every such address so the loader can add a delta")
    print("  (actual_base − preferred_base) to each one.  DLLs almost always")
    print("  need this; many EXEs are stripped (no .reloc) and must load at base.")

    # ------------------------------------------------------------------
    print()
    div()
    print("  STEP 6 — Hand off to the entry point")
    div()
    ep_va = img.opt.image_base + img.opt.entry_point_rva
    print(f"  Entry point RVA : {img.opt.entry_point_rva:#010x}")
    print(f"  Entry point VA  : {ep_va:#018x}  (image_base + RVA)")
    print()
    if is_dll:
        print("  For a DLL the loader calls DllMain(hModule, DLL_PROCESS_ATTACH, NULL).")
        print("  Wine's ntdll does this after mapping and import resolution.")
    else:
        print("  For an EXE the loader jumps to this address.  On Windows that lands")
        print("  in the CRT startup stub which calls WinMain / main.")
        print("  Wine redirects execution here after mapping all DLLs.")

    div("=")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="WoadyCompat PE Mapper: models loader reasoning for a Windows PE binary.",
        epilog="Safety: read-only static analysis. The input file is never executed.",
    )
    parser.add_argument("file", metavar="FILE",
                        help="Windows PE binary (.exe / .dll / .sys)")
    args = parser.parse_args()
    img = parse(args.file)
    report(img)


if __name__ == "__main__":
    main()
