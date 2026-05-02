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

## Validation

Phase 5 confirmed:

- NVIDIA GeForce RTX 5070 detected as a Vulkan discrete GPU
- AMD Ryzen 7 9800X3D iGPU detected through RADV
- llvmpipe detected as CPU fallback
- Minimal vertex shader successfully inspected as SPIR-V

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
