# reflective-code-loading

Payloads and scripts for in-memory code loading — loading PE files (DLL, EXE) and object files directly into process memory without writing to disk.

Two subdirectories:

```
reflective-code-loading/
├── discovery-loading-target/   # Benign payloads used as loading targets
└── art-scripts/                # Loaders and scripts that perform the loading
```

---

## discovery-loading-target

Benign discovery payloads in three formats. All variants collect local system information (hostname, OS version, user, running processes, services, filesystem) and write output to `%LOCALAPPDATA%`.

| File | Format | Compatible loaders |
|---|---|---|
| `bin\Release\WNetHelper-default.exe` | .NET 4.8 EXE (x64) | Sliver `execute-shellcode` (via Donut), `execute-assembly` |
| `wnet-discovery.dll` | Native x64 DLL, exports `VoidFunc` | Sliver `execute-shellcode` (via Donut), `Invoke-ReflectivePEInjection` (DLL mode) |
| `wnet-bof.o` | COFF BOF | Sliver `extensions load` + `wnet-bof` |

See `discovery-loading-target/README.md` for build instructions and source file reference.

---

## art-scripts

Loaders and DLLs ported from Atomic Red Team T1620.

### Invoke-ReflectivePEInjection.ps1

PowerShell PE loader (EmpireProject/PowerSploit). Implements full PE loading in pure PowerShell — parse headers, `VirtualAlloc`, map sections, resolve imports — without calling `LoadLibrary`.

**DLL mode** — calls `DllMain(DLL_PROCESS_ATTACH)` then the `VoidFunc` export. Supports remote injection into another process.

```powershell
Import-Module .\Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEPath ..\discovery-loading-target\wnet-discovery.dll -ForceASLR
```

**Patches applied** (required for PowerShell 5.1):
- Line 2384, 2443: `[UInt16]` cast before `-band` on `DllCharacteristics` to fix `InvalidCastException`

### CommanderDLL.dll

DLL that reconstructs its own Export Address Table at runtime. On `DLL_PROCESS_ATTACH`:

1. Finds scratch space at the image tail (past last section)
2. Writes a fabricated `IMAGE_EXPORT_DIRECTORY` there pointing to `StartRoutine`
3. Patches `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` in the loaded PE headers to point at the new table
4. Runs host discovery (same scope as `wnet-discovery.dll`), writes `%LOCALAPPDATA%\commander-dll.log`

After load, the EAT visible in memory differs from the on-disk binary.

```powershell
Add-Type -MemberDefinition @'
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern System.IntPtr LoadLibraryA(string lpFileName);
'@ -Name "Win32" -Namespace "EATTest"

[EATTest.Win32]::LoadLibraryA("$PWD\CommanderDLL.dll")
```

Build:
```
cl /LD /Os CommanderDLL.c /Fe:CommanderDLL.dll /link kernel32.lib advapi32.lib shlwapi.lib ntdll.lib
```

### reflective_load.dll

Minimal DLL from ART T1620. Exports `VoidFunc` (calls `GetCurrentProcessId`, returns). Used to verify the DLL loading path works without side effects.

```powershell
Invoke-ReflectivePEInjection -PEPath .\reflective_load.dll -ForceASLR
```
