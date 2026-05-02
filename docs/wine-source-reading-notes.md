# Phase 4 — Wine Source Reading Notes

Study guide for reading the Wine source tree as a systems engineer.
The goal is to understand *how* Wine solves the compatibility problem.
This is a reading guide — no code is written or executed here.

Wine source browser: https://source.winehq.org/git/wine.git
Mirror:              https://github.com/wine-mirror/wine

---

## 1. What Wine Actually Is

Wine is not an emulator. It does not emulate x86 hardware or simulate
a Windows kernel. It is a compatibility layer: a reimplementation of
the Windows API surface on top of a POSIX operating system.

The key insight:

  A Windows program only knows it can call CreateProcess, ReadFile,
  MessageBox, etc. Wine provides those exact function signatures.
  The CPU runs the program's native machine code directly.
  The program never finds out it is on Linux.

The hard part is not running the code. It is matching exact Windows
behaviour across thousands of API functions, including undocumented
edge cases that shipped applications depend on.

---

## 2. High-Level Wine Architecture

```
┌──────────────────────────────────────────────┐
│         Windows Application (PE binary)       │
└─────────────────┬────────────────────────────┘
                  │  Win32 API calls
┌─────────────────▼────────────────────────────┐
│            Wine DLL layer                     │
│  kernel32  user32  advapi32  gdi32  msvcrt    │
└─────────────────┬────────────────────────────┘
                  │  NT native API (Nt* / Rtl*)
┌─────────────────▼────────────────────────────┐
│              ntdll.dll                        │
│  PE loader  · heap · LDR · exceptions         │
└───────┬──────────────────────────┬────────────┘
        │  Linux syscalls           │  Unix socket
┌───────▼──────────┐    ┌──────────▼────────────┐
│   Linux kernel   │    │      wineserver         │
│   real OS calls  │    │  Windows object model   │
└──────────────────┘    └───────────────────────┘
```

### 2a. The PE Loader (ntdll/loader.c)

Reads a PE binary from disk and prepares it to run.

Conceptual responsibilities (static view — reading the source):
- Parses PE headers to understand binary layout
- Asks the OS to reserve virtual address space (via mmap)
- Copies each section from the file into memory at its virtual address
- Resolves the import table: locates each required DLL and function
- Processes the relocation table when the preferred base is unavailable
- Transfers control to the program's declared entry point

pe_inspector.py (Phase 1) and pe_mapper.py (Phase 3) give you the
vocabulary to read this source without getting lost.

### 2b. ntdll.dll

The lowest layer. Every other Wine DLL calls through ntdll.

Responsibilities:
- NT syscall interface: NtReadFile, NtCreateProcess, NtAllocateVirtualMemory
- The LDR: tracks all loaded modules, handles load-on-demand
- Heap manager: RtlAllocateHeap / RtlFreeHeap
- Exception dispatch: SEH and VEH
- Process and thread startup sequences

On real Windows, ntdll issues true kernel transitions via the syscall
instruction. In Wine, those same NT functions redirect to the Unix side:
either Linux syscalls directly, or IPC requests to wineserver.

### 2c. kernel32.dll

The primary Win32 layer that most applications call.

Built on ntdll. Most kernel32 functions are translation wrappers:

  CreateFile   -> NtCreateFile           -> open(2)
  CreateThread -> NtCreateThread         -> clone(2) / pthread
  VirtualAlloc -> NtAllocateVirtualMemory -> mmap(2)

Reading kernel32 source reveals the full translation chain. The pattern
is consistent: validate Win32 arguments, call the NT equivalent, convert
NT error codes back to Win32 error codes.

### 2d. user32.dll

The Windows GUI model: windows, messages, input, dialogs.

This is where compatibility engineering gets genuinely hard. Wine must
implement:
- The window message pump (GetMessage / DispatchMessage / PeekMessage)
- Window class registry and window creation/destruction lifecycle
- Keyboard and mouse input routing to the correct window
- GDI coordinate spaces and clipping regions
- Common dialogs: MessageBox, file open, font chooser

All display output is delegated to a graphics driver: winex11.drv for
X11, winewayland.drv for Wayland. user32 itself is display-agnostic.

### 2e. wineserver

A separate Unix process that lives alongside every Wine session.

It owns the parts of Windows semantics that require shared state across
processes — things the Linux kernel has no direct equivalent for:

- Named synchronisation objects: mutexes, events, semaphores
- Shared file mappings and their reference counts
- Windows-style process and thread handle tables
- The Windows registry (persisted under ~/.wine/system.reg etc.)
- Inter-process message delivery
- Security descriptor storage

Wine processes communicate with wineserver over a Unix domain socket.
When a Wine process calls WaitForSingleObject, ntdll sends a request to
wineserver and suspends. Wineserver tracks the object and sends a reply
when the condition is met, waking the caller.

---

## 3. Source Directories to Read

### loader/

Problem it solves: starting the Wine runtime before any Windows code runs.

Key files to read:
- main.c         the Unix entry point for the `wine` command
- preloader.c    reserves address space before the OS can claim it

Questions to ask while reading:
- What is the very first thing Wine does when you type `wine foo.exe`?
- How does a plain Unix process transform into a Windows process context?
- At what point does execution hand off to ntdll?
- Why does Wine need a preloader at all?

---

### dlls/ntdll/

Problem it solves: the foundation every Wine DLL stands on.

Key files to read:
- loader.c           PE image reading, virtual layout, import resolution
- heap.c             Windows heap semantics over Unix allocators
- thread.c           Windows thread model over pthreads
- exception.c        structured exception handling (SEH/VEH)
- signal_i386.c      Unix signal -> Win32 exception translation
- unix/loader.c      Unix-side counterpart to the Windows-side loader
- unix/virtual.c     virtual memory management (mmap wrappers)
- unix/server.c      wineserver IPC protocol

What to look for:
- LdrLoadDll              — DLL load-on-demand implementation
- LdrGetProcedureAddress  — how GetProcAddress works internally
- RtlAllocateHeap         — what a Windows heap does in practice
- NtMapViewOfSection      — section (file mapping) semantics

Questions to ask while reading:
- How does the LDR track which modules are already loaded?
- What data structure is the PEB module list? How is it walked?
- How does ntdll choose where in virtual address space to place a DLL?
- How are NT error codes (NTSTATUS) converted to Win32 error codes?
- What happens when an import cannot be resolved?

---

### dlls/kernel32/

Problem it solves: the Win32 API layer most applications target.

Key files to read:
- process.c      CreateProcess, OpenProcess, GetCurrentProcess
- thread.c       CreateThread, SuspendThread, GetExitCodeThread
- file.c         CreateFile, ReadFile, WriteFile, SetFilePointer
- heap.c         HeapAlloc/HeapFree (thin wrappers over ntdll Rtl*)
- module.c       LoadLibrary, GetProcAddress, FreeLibrary
- sync.c         CreateMutex, WaitForSingleObject, CreateEvent

What to look for:
- How each Win32 function maps to an Nt* call in ntdll
- How HRESULT / Win32 error codes are derived from NTSTATUS values
- Which functions must call wineserver (anything needing shared state)
- Which functions go straight to Linux syscalls (purely local operations)

Questions to ask while reading:
- Which kernel32 functions require a wineserver round-trip? Why?
- What does HeapAlloc actually call at the bottom?
- How does LoadLibrary avoid loading a DLL twice?

---

### dlls/user32/

Problem it solves: the Windows GUI programming model.

Key files to read:
- winproc.c      window procedure dispatch and subclassing
- message.c      PostMessage, SendMessage, message queue management
- class.c        RegisterClass, FindClass, window class storage
- win.c          CreateWindow, DestroyWindow, window state tracking
- input.c        keyboard and mouse input delivery
- dialog.c       DialogBox, EndDialog, dialog message loop
- msgbox.c       MessageBox implementation

What to look for:
- How the message queue is implemented (wineserver-backed)
- How SendMessage differs from PostMessage at the implementation level
- How window handles (HWND) map to internal Wine structures
- Where the call into the graphics driver (winex11.drv) occurs

Questions to ask while reading:
- What is a window procedure and how does Wine dispatch to it?
- How does the message loop interact with wineserver?
- How are HWND values allocated and tracked?
- What makes SendMessage to another thread more complex than local dispatch?

---

### server/

Problem it solves: shared Windows object state across all Wine processes.

Key files to read:
- main.c         wineserver entry point and event loop
- object.c       reference-counted Windows kernel object base type
- mutex.c        named mutex implementation
- event.c        manual-reset and auto-reset event objects
- process.c      Windows process object and handle table
- thread.c       Windows thread object and scheduling state
- registry.c     Windows registry backed by Unix files
- protocol.def   the IPC message schema (generated into a header)

What to look for:
- How wineserver's event loop (select/epoll) drives Windows object signalling
- How handle tables map Windows HANDLE values to internal objects
- How named objects allow sharing across processes
- How the registry file format maps to the Windows registry view

Questions to ask while reading:
- Why does wineserver run as a separate process rather than a shared library?
- How does a Wine process acquire a handle to a kernel object?
- What happens to wineserver objects when the last Wine process exits?
- How does wineserver ensure atomicity for operations like mutex acquisition?

---

## 4. Concept Translation Table

| Windows concept           | Wine / Linux equivalent               | Why it matters                                      |
|---------------------------|---------------------------------------|-----------------------------------------------------|
| PE section mapping        | mmap(2) with appropriate PROT flags   | Each section gets its own permissions page-aligned  |
| Import Address Table      | Array of function pointers filled at load time | Resolved by LdrLoadDll walking each DLL's exports |
| HANDLE                    | Index into wineserver handle table    | Handles are process-local; wineserver tracks objects|
| VirtualAlloc              | mmap(2) / mprotect(2)                 | Wine manages Windows virtual layout over Linux VM   |
| CreateThread              | pthread_create + Wine thread state    | Thread-local storage, Win32 TEB must be set up      |
| WaitForSingleObject       | wineserver IPC + futex or epoll       | Requires shared signalling state                    |
| Windows Registry          | ~/.wine/*.reg files + wineserver      | wineserver serialises concurrent registry access    |
| Structured Exception Handling | Unix signal handler -> SEH frame | SIGSEGV becomes EXCEPTION_ACCESS_VIOLATION          |
| DLL search order          | Wine's own search path logic          | System32 is a virtual directory under ~/.wine       |
| Window message queue      | wineserver queue + Unix event fd      | Cross-thread/process delivery needs shared state    |
| GetProcAddress            | LdrGetProcedureAddress in ntdll       | Walks the export table of an already-mapped module  |
| NTSTATUS error codes      | Converted to Win32 errors by kernel32 | Two parallel error systems must stay in sync        |

---

## 5. Study Commands

Install Wine on Ubuntu:

    sudo apt install wine winetricks

Check the version and configuration:

    wine --version
    winecfg

Run a Windows binary and trace which DLLs Wine loads:

    WINEDEBUG=+loaddll wine notepad.exe

Run and capture every Linux syscall Wine makes:

    strace -f -o wine-trace.txt wine notepad.exe
    less wine-trace.txt

Filter the trace to just memory mapping calls:

    grep -E 'mmap|mprotect|munmap' wine-trace.txt | head -40

Filter to just file opens (shows DLL search path in action):

    grep 'openat' wine-trace.txt | head -40

Watch wineserver IPC messages (recvmsg/sendmsg are the socket calls):

    grep -E 'recvmsg|sendmsg' wine-trace.txt | head -20

List Wine DLLs installed on the system:

    find /usr/lib/wine -name '*.so' | sort

Read the Wine debug channel list (shows all areas you can trace):

    wine --debugmsg 2>&1 | head -60

---

## 6. Learning Checklist

### Understand well (after Phases 1-3)
- [x] PE file format: DOS header, COFF header, optional header, sections
- [x] Import table structure: IMAGE_IMPORT_DESCRIPTOR, IAT, INT
- [x] Section virtual addresses vs file offsets
- [x] RVA-to-file-offset conversion
- [x] Win32 type system: DWORD, HANDLE, LPCSTR, etc.
- [x] API translation concept: Win32 -> NT -> Linux syscall

### Research next (Phase 4 targets)
- [ ] PEB (Process Environment Block) structure and what it contains
- [ ] TEB (Thread Environment Block) and thread-local storage
- [ ] LDR_DATA_TABLE_ENTRY: the module list node structure
- [ ] How SEH frames are laid out on the stack (x86 vs x64 differ)
- [ ] Export table format: how GetProcAddress resolves a name
- [ ] NTSTATUS code space and how RtlNtStatusToDosError works
- [ ] How wineserver protocol.def generates the IPC message structs
- [ ] Difference between DLL_PROCESS_ATTACH and DLL_THREAD_ATTACH

### Connection to Proton
Proton is Wine plus a curated set of patches and additions for gaming:

- DXVK        replaces Direct3D 9/10/11 with a Vulkan implementation
- VKD3D-Proton replaces Direct3D 12 with Vulkan
- FAudio       replaces XAudio2 with an SDL-backed implementation
- Steam Runtime provides a controlled Linux library environment
- Esync/Fsync  replace wineserver event objects with Linux eventfd/futex
               for lower latency (critical for games doing many waits/sec)

The Esync/Fsync work is the most instructive Proton-specific reading:
it shows exactly where wineserver becomes a bottleneck and how the
kernel's own primitives can be used as a faster alternative.

Start reading Proton after the LDR and wineserver concepts are solid.

---

## 7. Notes Log

Use this section to record observations as you read the source.
Format: date — file — observation.

Example:
  2026-05-02 — dlls/ntdll/loader.c — LdrLoadDll calls map_so_dll for
  native Unix .so files and map_image for PE DLLs. Two separate paths.
