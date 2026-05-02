# WoadyCompat

WoadyCompat is a learning-focused Windows compatibility research project for Linux.

The goal is to understand how Wine/Proton-style compatibility works by building small, safe, non-executing tools and architecture notes.

## Current Focus

- PE file inspection
- Static PE mapping concepts
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
Educational model of loader concepts without executing binaries.

### Phase 4 — Wine Source Reading Notes
Architecture notes for understanding Wine internals.

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

## Validation

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
