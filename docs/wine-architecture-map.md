# Wine Architecture Map

Understanding Windows compatibility on Linux requires grasping how Wine maps Windows concepts to Unix equivalents.

## The Core Problem

Windows programs are built around:
- **PE binary format** — metadata describing machine code, sections, imports
- **Win32 API** — thousands of functions for I/O, threading, memory, graphics
- **Windows subsystem** — kernel semantics, process model, registry

Linux provides:
- **ELF binary format** — different structure and calling conventions
- **POSIX API** — much smaller surface area
- **Linux kernel** — different semantics

**Wine's job:** Translate Windows binaries and API calls to Linux equivalents.

---

## Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│                  Windows Application                     │
│              (PE binary, Win32 API calls)                │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              Wine Loader (wineserver)                    │
│  • Parse PE binary (Section headers, imports, entry)    │
│  • Allocate virtual memory space                         │
│  • Load sections into memory with correct permissions   │
│  • Resolve DLL imports                                  │
│  • Execute process and jump to entry point              │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│           Win32 API Shim Layer (ntdll, kernel32, etc)  │
│  • Intercept Win32 function calls                       │
│  • Map to Linux system calls or Wine implementations    │
│  • Handle Windows-specific behavior                     │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│            Linux Kernel / System Libraries              │
│              (POSIX syscalls, pthread, etc)             │
└─────────────────────────────────────────────────────────┘
```

---

## Key Components in Detail

### 1. PE Binary Format (Static Analysis)

**What it contains:**
- DOS header + PE signature (magic validation)
- COFF header (machine type, section count, features)
- Optional header (entry point, base address, subsystem, alignment)
- Section table (.text, .data, .rsrc, .reloc, .idata, etc.)
- Import table (DLLs and functions required)
- Export table (functions this DLL exports)
- Relocation table (addresses to patch if not loaded at preferred base)

**Why it matters to Wine:**
- Loader must parse this to know what to load and where
- Import table tells Wine which DLLs to provide
- Section layout determines memory protection (R/W/X)
- Relocations needed if preferred address is unavailable

**Tools that analyze this:**
- `pe_inspector.py` — Extracts metadata
- `pe_mapper.py` — Models loader reasoning about virtual layout

---

### 2. Virtual Memory Layout

Windows uses a flat 32-bit (PE32) or 64-bit (PE32+) address space.

**Memory regions:**
```
0x00000000 - 0x00400000  → NULL page and shared system data
0x00400000 - 0x02000000  → User-mode code/data (typically)
0x02000000 - 0x7FFFFFFF  → User-mode heap/stack (varies)
0x80000000 - 0xFFFFFFFF  → Kernel-mode (unreachable from user apps)
```

**Wine's approach:**
- Each PE file wants to load at its "preferred image base" (usually 0x400000)
- If that address is taken, Wine applies `.reloc` section to rebase
- Linux provides virtual memory via `mmap()` — Wine calls this for each section
- Permissions come from section characteristics (R, W, X bits)

**Critical for understanding:**
- Why DLLs must be rebased if base address conflicts
- Why Section alignment matters (page-level granularity)
- How imports are resolved at runtime via IAT (Import Address Table)

---

### 3. Import Resolution (The Hardest Loader Job)

**Windows process:**
1. Loader reads Import Directory (`.idata` section)
2. For each DLL name, finds that DLL file
3. Loads the DLL into memory (recursive)
4. For each imported function:
   - Finds function address in DLL
   - Writes address to Import Address Table (IAT)
5. Application code reads function pointers from IAT

**Wine's equivalent:**
1. Parse import table from PE file
2. For each required DLL:
   - Check if Wine provides it (`kernel32.dll`, `user32.dll`, etc.)
   - Load Wine's implementation instead of Windows DLL
3. Wire up function calls to Wine's implementations

**Example:**
```
Windows app calls: CreateFileA("C:\\test.txt", ...)
  → Reads function pointer from IAT
  → Calls Wine's kernel32 CreateFileA
    → Wine maps "C:\\test.txt" to "/home/user/.wine/drive_c/test.txt"
    → Calls Linux open() syscall
    → Returns Linux file descriptor wrapped as Windows HANDLE
```

**Tools that expose this:**
- `pe_mapper.py` — Shows import table structure and DLLs required
- `wine_debug_analyzer.py` — Parses loader output to identify missing DLLs

---

### 4. Debug Log Analysis

When Wine runs with `WINEDEBUG=+loaddll,+seh`:

**Output shows:**
- Which DLLs loaded successfully
- Which DLLs failed to load (missing dependencies)
- Warnings and exceptions (often first sign of incompatibility)
- Entry point and thread creation events

**What it tells us:**
- Import resolution succeeded or failed
- Threading/exception handling issues
- Graphics/audio/networking failures

**Tool:**
- `wine_debug_analyzer.py` — Summarizes debug logs and categorizes issues

---

## Compatibility Challenges Across Layers

### Binary Format Differences

**Problem:** Windows PE vs Linux ELF
- Different sections, relocation models, import mechanisms
- Different calling conventions (x86 cdecl vs register-based)

**Wine's solution:**
- Static analysis of PE → Load into Linux memory
- Create thunk layer to translate calling conventions

---

### API Incompleteness

**Problem:** Windows has ~10,000 API functions; Wine implements a subset
- Graphics (DirectX) vs Linux (OpenGL/Vulkan)
- Registry vs Linux config files
- Windows handles vs Linux file descriptors
- Threading models differ subtly

**Wine's solution:**
- Implement the most-used APIs first
- Stub/stub out rarely-used functions
- Use DXVK/VKD3D for graphics translation

---

### Thread/Process Model

**Windows:**
- Kernel threads, kernel events, critical sections
- Per-thread exception handling
- Structured Exception Handling (SEH)

**Linux (POSIX):**
- Different thread semantics
- Signal-based exception model
- Different atomic operations

**Wine's solution:**
- Wrap pthreads to behave like Windows threads
- Implement Windows exception model on top
- SEH emulation layer

---

## How WoadyCompat Tools Fit In

```
Windows PE Binary (input)
    ↓
pe_inspector.py ────────→ "What imports does it need?"
    ↓
pe_mapper.py ────────────→ "How would a loader arrange this in memory?"
    ↓
wine_debug_analyzer.py ──→ "What went wrong during loading/execution?"
    ↓
Wine Source Notes ───────→ "How does Wine actually implement this?"
```

Each tool reveals one layer of the system:
1. **Phase 1 (PE Inspector):** Raw binary metadata
2. **Phase 3 (PE Mapper):** Loader's view of the binary
3. **Phase 6 (Debug Analyzer):** Runtime behavior and failures
4. **Phase 4 (Architecture Notes):** Why Wine design is that way

---

## Key Concepts for Recruiters

When you see WoadyCompat tools, you're seeing understanding of:

✓ **Binary formats** — PE structure, sections, relocations  
✓ **Virtual memory** — Address spaces, paging, protection  
✓ **Linking & loading** — Import resolution, dynamic linking  
✓ **Compatibility layers** — API mapping, syscall translation  
✓ **Systems programming** — Kernel interfaces, process model  
✓ **Debugging** — Log analysis, failure diagnosis  

None of this is about:
✗ Executing untrusted code  
✗ Process injection  
✗ DRM bypass  
✗ Malware analysis  

It's about understanding how software abstraction layers work.

---

## Further Reading (Wine Source)

- **loader/module.c** — PE loading logic
- **dlls/kernel32/process.c** — CreateProcess and DLL loading
- **dlls/ntdll/loader.c** — Low-level loader
- **dlls/kernel32/file.c** — File handle mapping to Win32
- **server/process.c** — Wineserver process model

---

## Next Steps

This architecture map should help frame the WoadyCompat tools as part of a coherent understanding of Wine/Proton, not as isolated utilities.

The tools demonstrate:
- **How to analyze** a binary (PE Inspector, PE Mapper)
- **How to debug** a compatibility failure (Debug Analyzer)
- **Why Wine is designed** the way it is (Architecture Notes)
