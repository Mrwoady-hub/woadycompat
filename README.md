# WoadyCompat

A learning-focused Windows compatibility layer project for Linux.

## Goal

WoadyCompat explores how Wine/Proton-style compatibility works by building small, understandable components:

- PE file inspection
- Windows binary metadata parsing
- Import table analysis
- Win32 API shim experiments
- Loader architecture notes
- Wine/Proton internals research

## Roadmap

- [x] Phase 0 — Study Wine/Proton architecture
- [ ] Phase 1 — PE Inspector (`tools/pe_inspector.py`)
- [ ] Phase 2 — Win32 API shim layer (C)
- [ ] Phase 3 — Toy PE loader
- [ ] Phase 4 — Wine source study
- [ ] Phase 5 — Graphics translation concepts (DXVK/VKD3D)
- [ ] Phase 6 — Proton-specific internals

## Usage

```bash
# Inspect a Windows PE binary
python3 tools/pe_inspector.py samples/notepad.exe
```

## Legal / Ethical Scope

This project is for compatibility research, systems programming education, and defensive cybersecurity learning.
