#include "win32_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Internal state
 * ----------------------------------------------------------------------- */

static struct timespec _shim_start;      /* set by shim_init() */
static __thread DWORD  _last_error = 0; /* per-thread, like Windows TLS */

void shim_init(void)
{
    clock_gettime(CLOCK_MONOTONIC, &_shim_start);
    fprintf(stderr, "[woadycompat] shim initialised\n");
}

/* -----------------------------------------------------------------------
 * kernel32 implementations
 * ----------------------------------------------------------------------- */

/*
 * Sleep(ms) — Windows suspends the thread for at least `ms` milliseconds.
 * Linux: usleep works in microseconds; nanosleep gives us full precision.
 */
void SHIM_Sleep(DWORD ms)
{
    struct timespec req = {
        .tv_sec  = ms / 1000,
        .tv_nsec = (ms % 1000) * 1000000L,
    };
    nanosleep(&req, NULL);
}

/*
 * GetTickCount() — returns milliseconds elapsed since process start.
 * Windows wraps at 2^32 ms (~49.7 days); we replicate that with cast to DWORD.
 */
DWORD SHIM_GetTickCount(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long sec_diff  = now.tv_sec  - _shim_start.tv_sec;
    long nsec_diff = now.tv_nsec - _shim_start.tv_nsec;

    long ms = sec_diff * 1000L + nsec_diff / 1000000L;
    return (DWORD)ms; /* intentional truncation mirrors Windows behaviour */
}

/*
 * ExitProcess(exitCode) — terminates all threads in the process.
 * Linux: exit() is sufficient for a single-process demo; a real loader
 * would call _exit() to avoid running atexit handlers from the host.
 */
void SHIM_ExitProcess(UINT exitCode)
{
    fprintf(stderr, "[woadycompat] ExitProcess(%u)\n", exitCode);
    exit((int)exitCode);
}

/*
 * GetLastError / SetLastError — Windows stores a per-thread error code.
 * We use __thread (GCC/Clang TLS extension) to mirror that behaviour.
 */
DWORD SHIM_GetLastError(void)
{
    return _last_error;
}

void SHIM_SetLastError(DWORD error)
{
    _last_error = error;
}

/*
 * OutputDebugStringA — on Windows this goes to an attached debugger.
 * We send it to stderr so tools like strace / ltrace can see it, just
 * as winedbg intercepts it when running under Wine.
 */
void SHIM_OutputDebugStringA(LPCSTR msg)
{
    fprintf(stderr, "[DEBUG] %s\n", msg ? msg : "(null)");
}

/*
 * HeapAlloc / HeapFree — Windows uses a per-process heap object (HANDLE).
 * We ignore the heap handle for now and delegate straight to malloc/free.
 * A real loader would manage a heap arena to match Windows allocation
 * granularity (8-byte aligned, committed pages, etc.).
 */
LPVOID SHIM_HeapAlloc(DWORD bytes)
{
    LPVOID ptr = malloc((size_t)bytes);
    if (!ptr) {
        SHIM_SetLastError(8); /* ERROR_NOT_ENOUGH_MEMORY */
    }
    return ptr;
}

void SHIM_HeapFree(LPVOID ptr)
{
    free(ptr);
}

/* -----------------------------------------------------------------------
 * user32 implementations
 * ----------------------------------------------------------------------- */

/*
 * MessageBoxA — on Linux we have no Win32 GUI stack, so we render the
 * dialog as terminal output and read a keypress.
 *
 * This is the exact approach Wine takes in its user32 stub when no
 * display is available: it falls back to a text representation.
 */
int SHIM_MessageBoxA(HWND hWnd, LPCSTR text, LPCSTR caption, UINT uType)
{
    (void)hWnd; /* ignored — no window hierarchy on Linux */

    const char *title = caption ? caption : "Message";
    const char *body  = text    ? text    : "";

    /* Determine which buttons to show based on uType flags */
    int buttons = uType & 0x0F; /* low nibble encodes button set */

    printf("\n");
    printf("┌─ %s %s\n",
           (uType & MB_ICONERROR)       ? "[ERROR]"   :
           (uType & MB_ICONWARNING)     ? "[WARNING]" :
           (uType & MB_ICONINFORMATION) ? "[INFO]"    : "[MSG]",
           title);
    printf("│\n");
    printf("│  %s\n", body);
    printf("│\n");

    if (buttons == MB_OKCANCEL) {
        printf("│  [O]K   [C]ancel\n");
        printf("└─ Choice: ");
        fflush(stdout);
        int ch = getchar();
        printf("\n");
        return (ch == 'c' || ch == 'C') ? IDCANCEL : IDOK;

    } else if (buttons == MB_YESNO) {
        printf("│  [Y]es   [N]o\n");
        printf("└─ Choice: ");
        fflush(stdout);
        int ch = getchar();
        printf("\n");
        return (ch == 'n' || ch == 'N') ? IDNO : IDYES;

    } else {
        /* MB_OK — default */
        printf("│  [Press Enter]\n");
        printf("└─ ");
        fflush(stdout);
        getchar();
        printf("\n");
        return IDOK;
    }
}
