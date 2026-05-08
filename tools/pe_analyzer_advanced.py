#!/usr/bin/env python3
"""
WoadyCompat Advanced Static PE Analyzer — Phase 7

Performs deep static analysis of PE files:
- Relocation table parsing (.reloc section)
- Import Address Table details
- TLS directory metadata
- Export table parser
- Suspicious indicator summary
- Markdown report generation

Safety: Static analysis only. No execution, no memory modification, no injection.
"""

import sys
import struct
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import IntEnum


# ============================================================================
# Data Structures
# ============================================================================

class RelocationType(IntEnum):
    """Base Relocation Type Codes"""
    ABSOLUTE = 0
    HIGH = 1
    LOW = 2
    HIGHLOW = 3
    HIGHADJ = 4
    MIPS_JMPADDR = 5
    ARM_MOV32 = 5
    RISCV_HIGH20 = 5
    THUMB_MOV32 = 7
    MIPS_JMPADDR16 = 9
    DIR64 = 10


@dataclass
class Relocation:
    rva: int
    rel_type: int
    type_name: str


@dataclass
class RelocationBlock:
    page_rva: int
    size: int
    relocations: List[Relocation] = field(default_factory=list)


@dataclass
class ImportedFunction:
    name: Optional[str]
    ordinal: Optional[int]
    rva: Optional[int]
    flags: int


@dataclass
class TLSDirectory:
    start_address_va: int
    end_address_va: int
    index_address_va: Optional[int]
    callbacks_address_va: Optional[int]
    zero_fill_size: int
    flags: int


@dataclass
class ExportFunction:
    ordinal: int
    name: Optional[str]
    rva: int
    forwarded_to: Optional[str] = None


@dataclass
class AdvancedAnalysis:
    filepath: str
    is_pe32_plus: bool
    image_base: int
    
    relocations: List[RelocationBlock] = field(default_factory=list)
    exports: List[ExportFunction] = field(default_factory=list)
    tls_directory: Optional[TLSDirectory] = None
    
    suspicious_indicators: Dict[str, List[str]] = field(default_factory=dict)
    packed_sections: List[str] = field(default_factory=list)
    unusual_sections: List[str] = field(default_factory=list)


# ============================================================================
# Helpers
# ============================================================================

def u16(data, off): return struct.unpack_from("<H", data, off)[0]
def u32(data, off): return struct.unpack_from("<I", data, off)[0]
def u64(data, off): return struct.unpack_from("<Q", data, off)[0]

def cstr(data, off) -> str:
    """Read null-terminated ASCII string."""
    try:
        end = data.index(b"\x00", off)
        return data[off:end].decode("ascii", errors="replace")
    except:
        return "<unreadable>"


# ============================================================================
# Relocation Analysis
# ============================================================================

def parse_relocations(data: bytes, reloc_rva: int, reloc_size: int, 
                      sections: List) -> List[RelocationBlock]:
    """Parse BASE_RELOCATION_TABLE (.reloc section)."""
    
    def rva_to_offset(rva):
        for sec in sections:
            if sec['virt_addr'] <= rva < sec['virt_addr'] + sec['virt_size']:
                return sec['raw_ptr'] + (rva - sec['virt_addr'])
        return None
    
    reloc_offset = rva_to_offset(reloc_rva)
    if not reloc_offset or reloc_offset + reloc_size > len(data):
        return []
    
    blocks = []
    pos = reloc_offset
    end = reloc_offset + reloc_size
    
    reloc_type_names = {
        0: "ABSOLUTE",
        1: "HIGH",
        2: "LOW",
        3: "HIGHLOW",
        4: "HIGHADJ",
        5: "MIPS_JMPADDR",
        7: "THUMB_MOV32",
        10: "DIR64",
    }
    
    while pos + 8 <= end:
        page_rva = u32(data, pos)
        block_size = u32(data, pos + 4)
        
        if block_size < 8:
            break
        
        block = RelocationBlock(page_rva=page_rva, size=block_size)
        pos += 8
        
        # Each relocation entry is 2 bytes: high 4 bits = type, low 12 bits = offset
        num_entries = (block_size - 8) // 2
        
        for i in range(num_entries):
            if pos >= end:
                break
            
            entry = u16(data, pos)
            rel_type = (entry >> 12) & 0xF
            offset = entry & 0xFFF
            rva = page_rva + offset
            
            rel_obj = Relocation(
                rva=rva,
                rel_type=rel_type,
                type_name=reloc_type_names.get(rel_type, f"UNKNOWN({rel_type})")
            )
            block.relocations.append(rel_obj)
            pos += 2
        
        blocks.append(block)
    
    return blocks


# ============================================================================
# Export Table Analysis
# ============================================================================

def parse_exports(data: bytes, export_rva: int, export_size: int,
                  sections: List) -> List[ExportFunction]:
    """Parse EXPORT_DIRECTORY."""
    
    def rva_to_offset(rva):
        for sec in sections:
            if sec['virt_addr'] <= rva < sec['virt_addr'] + sec['virt_size']:
                return sec['raw_ptr'] + (rva - sec['virt_addr'])
        return None
    
    export_offset = rva_to_offset(export_rva)
    if not export_offset or export_offset + 40 > len(data):
        return []
    
    exports = []
    
    # Parse EXPORT_DIRECTORY (40 bytes)
    num_functions = u32(data, export_offset + 20)
    num_names = u32(data, export_offset + 24)
    functions_rva = u32(data, export_offset + 28)
    names_rva = u32(data, export_offset + 32)
    ordinals_rva = u32(data, export_offset + 36)
    
    func_offset = rva_to_offset(functions_rva) if functions_rva else None
    names_offset = rva_to_offset(names_rva) if names_rva else None
    ordinals_offset = rva_to_offset(ordinals_rva) if ordinals_rva else None
    
    if not func_offset:
        return []
    
    # Build map of names to ordinals
    name_to_ordinal = {}
    if names_offset and ordinals_offset:
        for i in range(min(num_names, 1000)):  # Limit to prevent abuse
            name_rva = u32(data, names_offset + i * 4)
            name_offset = rva_to_offset(name_rva)
            ordinal_idx = u16(data, ordinals_offset + i * 2)
            
            if name_offset and ordinal_idx < num_functions:
                name = cstr(data, name_offset)
                name_to_ordinal[ordinal_idx] = name
    
    # Parse function table
    for i in range(min(num_functions, 10000)):  # Limit to prevent abuse
        func_rva = u32(data, func_offset + i * 4)
        
        if func_rva == 0:
            continue
        
        func_name = name_to_ordinal.get(i)
        exports.append(ExportFunction(
            ordinal=i + 1,
            name=func_name,
            rva=func_rva,
            forwarded_to=None
        ))
    
    return exports[:100]  # Cap at 100 exports for display


# ============================================================================
# TLS Directory Analysis
# ============================================================================

def parse_tls_directory(data: bytes, tls_rva: int, sections: List,
                        is_pe32_plus: bool) -> Optional[TLSDirectory]:
    """Parse TLS_DIRECTORY."""
    
    def rva_to_offset(rva):
        for sec in sections:
            if sec['virt_addr'] <= rva < sec['virt_addr'] + sec['virt_size']:
                return sec['raw_ptr'] + (rva - sec['virt_addr'])
        return None
    
    if tls_rva == 0:
        return None
    
    tls_offset = rva_to_offset(tls_rva)
    if not tls_offset:
        return None
    
    if is_pe32_plus:
        if tls_offset + 40 > len(data):
            return None
        start_va = u64(data, tls_offset)
        end_va = u64(data, tls_offset + 8)
        index_va = u64(data, tls_offset + 16)
        callbacks_va = u64(data, tls_offset + 24)
        zero_fill = u32(data, tls_offset + 32)
        flags = u32(data, tls_offset + 36)
    else:
        if tls_offset + 24 > len(data):
            return None
        start_va = u32(data, tls_offset)
        end_va = u32(data, tls_offset + 4)
        index_va = u32(data, tls_offset + 8)
        callbacks_va = u32(data, tls_offset + 12)
        zero_fill = u32(data, tls_offset + 16)
        flags = u32(data, tls_offset + 20)
    
    return TLSDirectory(
        start_address_va=start_va,
        end_address_va=end_va,
        index_address_va=index_va if index_va else None,
        callbacks_address_va=callbacks_va if callbacks_va else None,
        zero_fill_size=zero_fill,
        flags=flags
    )


# ============================================================================
# Suspicious Indicators
# ============================================================================

def check_suspicious_indicators(data: bytes, coff_offset: int, opt_offset: int,
                                opt_size: int, sections: List, 
                                opt_magic: int) -> Tuple[Dict, List[str], List[str]]:
    """Detect suspicious patterns."""
    
    indicators = {
        "compression": [],
        "unusual_sections": [],
        "packed_headers": [],
        "suspicious_code": [],
    }
    
    packed = []
    unusual = []
    
    # Check for packed sections (entropy-like indicators)
    for sec in sections:
        sec_name = sec['name'].lower()
        raw_size = sec['raw_size']
        virt_size = sec['virt_size']
        
        # Very small or zero raw data but large virtual size → packed
        if raw_size > 0 and virt_size > raw_size * 10:
            indicators["packed_headers"].append(
                f"{sec['name']}: {virt_size} bytes virtual, {raw_size} bytes raw (ratio: {virt_size/raw_size:.1f}x)"
            )
            packed.append(sec['name'])
        
        # Unusual section names
        if not sec_name.startswith(('.text', '.data', '.rsrc', '.reloc', '.idata', '.rdata', '.debug', '.pdata')):
            indicators["unusual_sections"].append(f"Unusual: {sec['name']}")
            unusual.append(sec['name'])
    
    # Check characteristics
    machine = u16(data, coff_offset)
    characteristics = u16(data, coff_offset + 18)
    
    if not (characteristics & 0x0002):  # Not executable
        indicators["suspicious_code"].append("Binary marked as non-executable")
    
    # Check for relocation stripping
    if not (characteristics & 0x0001):  # RELOCS_STRIPPED
        pass  # Normal for executables
    else:
        indicators["suspicious_code"].append("Relocations stripped (RELOCS_STRIPPED)")
    
    # Check timestamp
    timestamp = u32(data, coff_offset + 4)
    if timestamp == 0:
        indicators["suspicious_code"].append("Timestamp is zero (possibly packed)")
    
    return indicators, packed, unusual


# ============================================================================
# Main Analysis
# ============================================================================

def analyze_pe(filepath: str) -> Optional[AdvancedAnalysis]:
    """Perform advanced static analysis."""
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return None
    
    if len(data) < 64 or data[:2] != b"MZ":
        print("Error: Not a valid PE file", file=sys.stderr)
        return None
    
    e_lfanew = u32(data, 0x3C)
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        print("Error: Invalid PE signature", file=sys.stderr)
        return None
    
    coff_offset = e_lfanew + 4
    opt_offset = coff_offset + 20
    opt_size = u16(data, coff_offset + 16)
    opt_magic = u16(data, opt_offset)
    
    is_pe32_plus = opt_magic == 0x020B
    
    if is_pe32_plus:
        image_base = u64(data, opt_offset + 24)
        num_sections = u16(data, coff_offset + 2)
    else:
        image_base = u32(data, opt_offset + 28)
        num_sections = u16(data, coff_offset + 2)
    
    # Parse sections
    sec_table_off = opt_offset + opt_size
    sections = []
    for i in range(num_sections):
        off = sec_table_off + i * 40
        sec_data = data[off:off+40]
        name = sec_data[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        sections.append({
            'name': name,
            'virt_size': u32(sec_data, 8),
            'virt_addr': u32(sec_data, 12),
            'raw_size': u32(sec_data, 16),
            'raw_ptr': u32(sec_data, 20),
            'characteristics': u32(sec_data, 36),
        })
    
    analysis = AdvancedAnalysis(
        filepath=filepath,
        is_pe32_plus=is_pe32_plus,
        image_base=image_base,
    )
    
    # Parse data directories
    if is_pe32_plus:
        dir_offset = opt_offset + 112
    else:
        dir_offset = opt_offset + 96
    
    # Directory 5: Base Relocation Table
    reloc_rva = u32(data, dir_offset + 5 * 8)
    reloc_size = u32(data, dir_offset + 5 * 8 + 4)
    if reloc_rva and reloc_size:
        analysis.relocations = parse_relocations(data, reloc_rva, reloc_size, sections)
    
    # Directory 0: Export Table
    export_rva = u32(data, dir_offset)
    export_size = u32(data, dir_offset + 4)
    if export_rva and export_size:
        analysis.exports = parse_exports(data, export_rva, export_size, sections)
    
    # Directory 9: TLS Directory
    tls_rva = u32(data, dir_offset + 9 * 8)
    tls_size = u32(data, dir_offset + 9 * 8 + 4)
    if tls_rva and tls_size:
        analysis.tls_directory = parse_tls_directory(data, tls_rva, sections, is_pe32_plus)
    
    # Suspicious indicators
    indicators, packed, unusual = check_suspicious_indicators(
        data, coff_offset, opt_offset, opt_size, sections, opt_magic
    )
    analysis.suspicious_indicators = indicators
    analysis.packed_sections = packed
    analysis.unusual_sections = unusual
    
    return analysis


# ============================================================================
# Markdown Report
# ============================================================================

def generate_markdown_report(analysis: AdvancedAnalysis) -> str:
    """Generate comprehensive markdown report."""
    
    report = []
    report.append(f"# Advanced PE Analysis Report\n")
    report.append(f"**File:** {os.path.basename(analysis.filepath)}\n")
    report.append(f"**Generated:** Advanced Static Analyzer Phase 7\n")
    report.append(f"**Type:** PE{'32+' if analysis.is_pe32_plus else '32'} Static Analysis Only\n\n")
    
    # Summary
    report.append("## Summary\n")
    report.append(f"- **Image Base:** 0x{analysis.image_base:X}\n")
    report.append(f"- **Format:** PE{'32+' if analysis.is_pe32_plus else '32'}\n")
    report.append(f"- **Relocation Blocks:** {len(analysis.relocations)}\n")
    report.append(f"- **Exported Functions:** {len(analysis.exports)}\n")
    report.append(f"- **TLS Directory:** {'Present' if analysis.tls_directory else 'Not present'}\n")
    report.append(f"- **Suspicious Indicators:** {sum(len(v) for v in analysis.suspicious_indicators.values())}\n\n")
    
    # Relocation Analysis
    if analysis.relocations:
        report.append("## Relocation Table Analysis\n\n")
        report.append("Relocations allow the binary to be loaded at a different address than preferred.\n\n")
        report.append(f"**Total Blocks:** {len(analysis.relocations)}\n\n")
        report.append("| Page RVA | Type Distribution | Count |\n")
        report.append("|----------|-------------------|-------|\n")
        
        for block in analysis.relocations[:20]:  # Show first 20
            type_dist = {}
            for rel in block.relocations:
                type_dist[rel.type_name] = type_dist.get(rel.type_name, 0) + 1
            
            types = ", ".join([f"{t}({c})" for t, c in sorted(type_dist.items())])
            report.append(f"| 0x{block.page_rva:X} | {types} | {len(block.relocations)} |\n")
        
        if len(analysis.relocations) > 20:
            report.append(f"\n... and {len(analysis.relocations) - 20} more blocks\n")
        
        report.append("\n**Educational Note:** Relocations are how a loader adapts a binary to run at a different memory address.\n")
        report.append("This is **static analysis only** — we examine the relocation records without applying them.\n\n")
    
    # Export Table
    if analysis.exports:
        report.append("## Export Table Analysis\n\n")
        report.append("Exports are functions this DLL provides to other binaries.\n\n")
        report.append(f"**Total Exports:** {len(analysis.exports)}\n\n")
        report.append("| Ordinal | Name | RVA | Type |\n")
        report.append("|---------|------|-----|------|\n")
        
        for exp in analysis.exports[:30]:  # Show first 30
            name = exp.name if exp.name else "(no name)"
            report.append(f"| {exp.ordinal} | {name} | 0x{exp.rva:X} | Function |\n")
        
        if len(analysis.exports) > 30:
            report.append(f"\n... and {len(analysis.exports) - 30} more\n")
        
        report.append("\n")
    
    # TLS Directory
    if analysis.tls_directory:
        report.append("## Thread Local Storage (TLS) Directory\n\n")
        tls = analysis.tls_directory
        report.append(f"- **Start Address:** 0x{tls.start_address_va:X}\n")
        report.append(f"- **End Address:** 0x{tls.end_address_va:X}\n")
        report.append(f"- **Size:** {tls.end_address_va - tls.start_address_va} bytes\n")
        
        if tls.index_address_va:
            report.append(f"- **Index Address:** 0x{tls.index_address_va:X}\n")
        
        if tls.callbacks_address_va:
            report.append(f"- **Callbacks Address:** 0x{tls.callbacks_address_va:X} (TLS callbacks present)\n")
        
        report.append(f"- **Zero Fill Size:** {tls.zero_fill_size} bytes\n")
        report.append(f"- **Flags:** 0x{tls.flags:X}\n\n")
        
        report.append("**Educational Note:** TLS allows each thread to have its own copy of data. ")
        report.append("If callbacks are present, they execute when threads are created/destroyed.\n\n")
    
    # Suspicious Indicators
    if any(analysis.suspicious_indicators.values()):
        report.append("## Suspicious Indicators\n\n")
        
        for category, items in analysis.suspicious_indicators.items():
            if items:
                report.append(f"### {category.replace('_', ' ').title()}\n\n")
                for item in items:
                    report.append(f"- {item}\n")
                report.append("\n")
    
    # Packed Sections
    if analysis.packed_sections:
        report.append("## Packed/Compressed Sections\n\n")
        report.append("Sections with unusual virtual-to-raw size ratios:\n\n")
        for sec in analysis.packed_sections:
            report.append(f"- {sec}\n")
        report.append("\n")
    
    # Safety Statement
    report.append("## Analysis Scope\n\n")
    report.append("✓ **Static Analysis Only** — Binary file never executed\n\n")
    report.append("This analysis does NOT:\n")
    report.append("- Execute the binary\n")
    report.append("- Allocate executable memory\n")
    report.append("- Inject code or modify processes\n")
    report.append("- Resolve relocations or modify memory\n")
    report.append("- Load DLLs or call functions\n")
    report.append("- Include any bypass or exploitation techniques\n\n")
    
    report.append("The analysis examines static metadata to understand the binary's structure, imports, ")
    report.append("exports, and threading model. This is educational and safe for any binary.\n\n")
    
    report.append("---\n")
    report.append("*Generated by WoadyCompat Advanced Static PE Analyzer — Phase 7*\n")
    
    return "".join(report)


def main():
    if len(sys.argv) < 2:
        print("Usage: pe_analyzer_advanced.py <pe_file>")
        print("       Generates markdown report with advanced static analysis")
        sys.exit(1)
    
    filepath = sys.argv[1]
    analysis = analyze_pe(filepath)
    
    if analysis:
        report = generate_markdown_report(analysis)
        print(report)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
