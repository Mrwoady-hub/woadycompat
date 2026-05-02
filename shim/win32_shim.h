#ifndef WIN32_SHIM_H
#define WIN32_SHIM_H

/*
 * WoadyCompat Win32 Shim — Phase 2
 *
 * Defines a subset of the Windows type system and Win32 API surface,
 * implemented using Linux primitives underneath.
 *
 * This is the same job Wine does for every Win32 DLL:
 *   kernel32, user32, advapi32, msvcrt, ...
 */

#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stddef.h>

/* -----------------------------------------------------------------------
 * Windows primitive types
 * Wine maps these in include/windef.h — we mirror the concept here.
 * ----------------------------------------------------------------------- */

typedef unsigned int    UINT;
typedef unsigned long   DWORD;
typedef long            LONG;
typedef int             BOOL;
typedef unsigned char   BYTE;
typedef unsigned short  WORD;
typedef void *          HANDLE;
typedef void *          HWND;       /* window handle — opaque on Linux */
typedef void *          LPVOID;
typedef const char *    LPCSTR;
typedef char *          LPSTR;

#define TRUE  1
#define FALSE 0

/* MessageBox button/type flags (subset) */
#define MB_OK               0x00000000
#define MB_OKCANCEL         0x00000001
#define MB_YESNO            0x00000004
#define MB_ICONINFORMATION  0x00000040
#define MB_ICONWARNING      0x00000030
#define MB_ICONERROR        0x00000010

/* MessageBox return values */
#define IDOK     1
#define IDCANCEL 2
#define IDYES    6
#define IDNO     7

/* INVALID_HANDLE_VALUE sentinel */
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)

/* -----------------------------------------------------------------------
 * kernel32 — process / timing / memory
 * ----------------------------------------------------------------------- */

/* Suspend execution for `ms` milliseconds. */
void  SHIM_Sleep(DWORD ms);

/* Milliseconds since the shim was initialised (wraps at ~49 days like Windows). */
DWORD SHIM_GetTickCount(void);

/* Terminate the calling process with the given exit code. */
void  SHIM_ExitProcess(UINT exitCode);

/* Per-thread "last error" — Wine mirrors this exactly in ntdll. */
DWORD SHIM_GetLastError(void);
void  SHIM_SetLastError(DWORD error);

/* Write a debug string (visible on stderr, like OutputDebugStringA). */
void  SHIM_OutputDebugStringA(LPCSTR msg);

/* Heap allocation wrappers (thin layer over malloc/free for now). */
LPVOID SHIM_HeapAlloc(DWORD bytes);
void   SHIM_HeapFree(LPVOID ptr);

/* -----------------------------------------------------------------------
 * user32 — windowing / dialogs (terminal fallback)
 * ----------------------------------------------------------------------- */

/*
 * Show a message box.  On Linux we have no Win32 GUI, so we print to the
 * terminal and prompt for input — exactly the kind of fallback Wine uses
 * in headless/console mode before X11/Wayland support kicks in.
 */
int SHIM_MessageBoxA(HWND hWnd, LPCSTR text, LPCSTR caption, UINT uType);

/* -----------------------------------------------------------------------
 * Internal init (call once at program start)
 * ----------------------------------------------------------------------- */
void shim_init(void);

#endif /* WIN32_SHIM_H */
