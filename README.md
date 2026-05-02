# WoadyCompat

WoadyCompat is a learning-focused Windows compatibility research project for Linux.

The goal is to understand how Wine/Proton-style compatibility works by building small, safe, non-executing tools and architecture notes.

## Current Focus

- PE file inspection and static mapping
- Win32 API concept mapping
- Wine source reading notes
- Vulkan device enumeration
- SPIR-V shader bytecode inspection
- Wine/Proton debug log analysis

## Project Phases

### Phase 1 — PE Inspector
Static parser for Windows PE metadata.

### Phase 2 — API Shim Concepts
Small compatibility-layer experiments for understanding how Windows-style API calls can map to Linux-side behavior.

### Phase 3 — Static PE Mapper
Educational model of loader concepts. Analyzes PE headers, sections, RVA mapping, and imports without executing binaries.

### Phase 4 — Wine Architecture & Debugging
Architecture documentation and debugging workflow. Connects all tools into coherent compatibility research.

See:
- [docs/wine-architecture-map.md](docs/wine-architecture-map.md) — How Wine maps Windows concepts to Linux
- [docs/wine-debugging-workflow.md](docs/wine-debugging-workflow.md) — Using tools to diagnose compatibility issues

### Phase 5 — Vulkan and SPIR-V Study
Graphics compatibility research focused on Vulkan device enumeration and SPIR-V shader inspection.

### Phase 6 — Wine/Proton Debug Log Analyzer
Educational tool to parse Wine debug logs and summarize compatibility issues without executing binaries.

## Tools

### Vulkan Device Enumerator

```bash
gcc tools/vulkan_info.c -o tools/vulkan_info -lvulkan
./tools/vulkan_info
```

### SPIR-V Inspector

```bash
python3 tools/spirv_inspect.py /tmp/minimal.spv
```

### PE Inspector

```bash
python3 tools/pe_inspector.py samples/nmap_service.exe
```

### Static PE Mapper

```bash
python3 tools/pe_mapper.py samples/nmap_service.exe
```

Analyzes:
- DOS and PE signature validation
- COFF and Optional header structure
- Section table and RVA-to-file-offset mapping
- Import directory metadata
- Loader reasoning walkthrough (educational)
- Relocation metadata

### Wine/Proton Debug Log Analyzer

```bash
# Analyze a Wine debug log file
python3 tools/wine_debug_analyzer.py docs/sample_wine_debug.log

# Or pipe Wine output directly
WINEDEBUG=+loaddll,+seh wine app.exe 2>&1 | python3 tools/wine_debug_analyzer.py -
```

Summarizes:
- DLLs loaded and missing
- Errors and warnings
- First failure point
- Estimated compatibility category (graphics, networking, filesystem, etc.)

## How the Tools Connect

**Diagnosis workflow:**

```
Windows PE Binary (game.exe, app.exe, etc.)
         ↓
   pe_inspector.py → "What does this binary need?"
         ↓
   pe_mapper.py → "How would a loader arrange this in memory?"
         ↓
Run with Wine debug output
         ↓
   wine_debug_analyzer.py → "What went wrong and where?"
         ↓
   [Architecture map] → "Why is Wine designed that way?"
         ↓
   [Debugging workflow] → "How do I fix this?"
```

Each tool reveals one layer:
1. **Static analysis** — What the binary contains
2. **Loader model** — How it should be arranged
3. **Runtime behavior** — What actually happened
4. **Architecture** — Why Wine/Proton works the way it does
5. **Workflow** — How to diagnose and fix issues

## Understanding the Project

Start here based on your interest:

- **Want to understand PE files?** → [pe_inspector.py](tools/pe_inspector.py)
- **Want to understand loading?** → [pe_mapper.py](tools/pe_mapper.py) + [wine-architecture-map.md](docs/wine-architecture-map.md)
- **Want to debug compatibility?** → [wine_debug_analyzer.py](tools/wine_debug_analyzer.py) + [wine-debugging-workflow.md](docs/wine-debugging-workflow.md)
- **Want to understand graphics?** → [vulkan_info.c](tools/vulkan_info.c) + [spirv_inspect.py](tools/spirv_inspect.py)

## Validation

Phase 3 confirmed:

- PE file format validation (MZ, PE signatures)
- Virtual address space reservation model
- Section mapping with RVA translation
- Import table structure analysis
- Educational loader reasoning walkthrough

Phase 4 confirmed:

- Wine architecture layers clearly mapped
- Binary format → Loader → API shim → Linux syscalls
- Debugging workflow connects all tools systematically
- Import resolution concepts explained
- Real-world diagnosis examples documented

Phase 5 confirmed:

- NVIDIA GeForce RTX 5070 detected as a Vulkan discrete GPU
- AMD Ryzen 7 9800X3D iGPU detected through RADV
- llvmpipe detected as CPU fallback
- Minimal vertex shader successfully inspected as SPIR-V

Phase 6 confirmed:

- Wine debug log analyzer successfully parses DLL loading events
- Correctly identifies missing modules and errors
- Categorizes compatibility issues (graphics, networking, filesystem, etc.)
- Generates actionable summaries for troubleshooting

## Safety Scope

This project is for educational compatibility research, systems programming, and defensive cybersecurity learning.

It does not include:

- malware behavior
- process injection
- shellcode
- DRM bypass
- anti-cheat bypass
- arbitrary binary execution

## Status

Active learning project.
