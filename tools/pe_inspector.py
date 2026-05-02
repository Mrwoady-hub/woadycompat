#!/usr/bin/env python3
"""
WoadyCompat PE Inspector
Phase 1 tool: parse and display Windows PE binary metadata.
Teaches the file format that a loader must understand.
"""

import sys
import pefile
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()


def fmt_hex(n):
    return f"0x{n:08X}"


def machine_name(code):
    machines = {
        0x014C: "x86 (i386)",
        0x8664: "x86-64 (AMD64)",
        0xAA64: "ARM64",
        0x01C4: "ARM (Thumb-2)",
    }
    return machines.get(code, f"Unknown ({fmt_hex(code)})")


def subsystem_name(code):
    subsystems = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows Console (CUI)",
        5: "OS/2 Console",
        7: "POSIX Console",
        9: "Windows CE GUI",
        10: "EFI Application",
        14: "Xbox",
    }
    return subsystems.get(code, f"Unknown ({code})")


def inspect(path):
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        console.print(f"[red]Not a valid PE file:[/red] {e}")
        sys.exit(1)

    nt = pe.NT_HEADERS
    opt = pe.OPTIONAL_HEADER
    file_hdr = pe.FILE_HEADER

    # --- Header summary ---
    is_64 = opt.Magic == 0x20B
    console.print(Panel(
        f"[bold cyan]{path}[/bold cyan]\n"
        f"Format:      [green]{'PE32+' if is_64 else 'PE32'}[/green]\n"
        f"Machine:     {machine_name(file_hdr.Machine)}\n"
        f"Entry Point: [yellow]{fmt_hex(opt.AddressOfEntryPoint)}[/yellow]\n"
        f"Image Base:  {fmt_hex(opt.ImageBase)}\n"
        f"Subsystem:   {subsystem_name(opt.Subsystem)}\n"
        f"Sections:    {file_hdr.NumberOfSections}\n"
        f"Timestamp:   {file_hdr.TimeDateStamp}",
        title="[bold]PE Header[/bold]",
        border_style="cyan",
    ))

    # --- Sections ---
    sec_table = Table(title="Sections", show_lines=True)
    sec_table.add_column("Name", style="bold")
    sec_table.add_column("VirtAddr", style="yellow")
    sec_table.add_column("VirtSize", style="yellow")
    sec_table.add_column("RawSize")
    sec_table.add_column("Characteristics")

    for sec in pe.sections:
        name = sec.Name.decode(errors="replace").rstrip("\x00")
        chars = []
        c = sec.Characteristics
        if c & 0x20:       chars.append("CODE")
        if c & 0x40:       chars.append("IDATA")
        if c & 0x80:       chars.append("UDATA")
        if c & 0x20000000: chars.append("EXEC")
        if c & 0x40000000: chars.append("READ")
        if c & 0x80000000: chars.append("WRITE")

        sec_table.add_row(
            name,
            fmt_hex(sec.VirtualAddress),
            fmt_hex(sec.Misc_VirtualSize),
            str(sec.SizeOfRawData),
            " | ".join(chars) if chars else "-",
        )
    console.print(sec_table)

    # --- Imports ---
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        console.print("[dim]No import table found.[/dim]")
        return

    imp_table = Table(title="Imports", show_lines=True)
    imp_table.add_column("DLL", style="bold magenta")
    imp_table.add_column("Functions")

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode(errors="replace"))
            else:
                funcs.append(f"ordinal#{imp.ordinal}")

        imp_table.add_row(dll, "\n".join(funcs[:20]) + ("\n..." if len(funcs) > 20 else ""))

    console.print(imp_table)

    # --- DLL check (is this a DLL?) ---
    if file_hdr.Characteristics & 0x2000:
        console.print("[bold yellow]Note:[/bold yellow] This file is a DLL (not an EXE).")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] pe_inspector.py <path-to-pe-file>")
        sys.exit(1)
    inspect(sys.argv[1])
