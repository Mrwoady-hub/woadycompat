/*
 * WoadyCompat — Phase 2 demo
 *
 * Simulates a tiny Windows program calling Win32 APIs.
 * All calls go through our shim layer instead of the real Windows DLLs.
 */

#include <stdio.h>
#include "win32_shim.h"

int main(void)
{
    shim_init();

    printf("\n=== WoadyCompat Phase 2: Win32 API Shim Demo ===\n\n");

    /* --- GetTickCount --- */
    DWORD t0 = SHIM_GetTickCount();
    printf("[kernel32] GetTickCount() = %lu ms since start\n", (unsigned long)t0);

    /* --- Sleep --- */
    printf("[kernel32] Sleep(250) — sleeping 250ms...\n");
    SHIM_Sleep(250);
    DWORD t1 = SHIM_GetTickCount();
    printf("[kernel32] GetTickCount() after sleep = %lu ms (delta ~%lu ms)\n",
           (unsigned long)t1, (unsigned long)(t1 - t0));

    /* --- OutputDebugStringA --- */
    SHIM_OutputDebugStringA("Hello from a fake Windows program");

    /* --- SetLastError / GetLastError --- */
    SHIM_SetLastError(5); /* ERROR_ACCESS_DENIED */
    printf("[kernel32] GetLastError() = %lu\n", (unsigned long)SHIM_GetLastError());
    SHIM_SetLastError(0);

    /* --- HeapAlloc / HeapFree --- */
    LPVOID buf = SHIM_HeapAlloc(64);
    if (buf) {
        printf("[kernel32] HeapAlloc(64) = %p — writing \"Hello\"\n", buf);
        /* writing into our allocation just like a Win32 program would */
        char *s = (char *)buf;
        s[0] = 'H'; s[1] = 'i'; s[2] = '\0';
        printf("[kernel32] HeapAlloc buffer contains: \"%s\"\n", s);
        SHIM_HeapFree(buf);
        printf("[kernel32] HeapFree() done\n");
    }

    /* --- MessageBoxA (interactive) --- */
    printf("\n[user32] Calling MessageBoxA...\n");
    int result = SHIM_MessageBoxA(
        NULL,
        "WoadyCompat is working!\nThis is a fake Win32 message box.",
        "WoadyCompat",
        MB_OKCANCEL | MB_ICONINFORMATION
    );
    printf("[user32] MessageBoxA returned: %s\n",
           result == IDOK ? "IDOK" : "IDCANCEL");

    /* --- ExitProcess --- */
    printf("\n[kernel32] Calling ExitProcess(0)...\n");
    SHIM_ExitProcess(0);

    return 0; /* unreachable */
}
