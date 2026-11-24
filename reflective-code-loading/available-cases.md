# T1620 Reflective Code Loading — Available Cases

**Technique:** T1620 Reflective Code Loading (TA0005 Stealth)

5 cases from Sliver agent (3) and Atomic Red Team (2).

---

## Sliver Agent (requires active session)

### V1 — execute-shellcode (local self-inject)

**Mechanism:** VirtualAlloc(RWX/RW) → byte-copy shellcode → VirtualProtect(RX) → CreateThread

**Command:**
```
execute-shellcode [--rwx-pages] <payload.bin>
```

If the input is a PE, the Sliver client auto-converts it via Donut (built-in). Before execution: patchAmsi() + patchEtw().

**Limitation:** Accepts only one arg (file path); cannot pass args into the shellcode. Donut bakes args at conversion time, but the Sliver client does not expose this option. Suitable for payloads that need no args (implant, reverse shell) or raw shellcode.

**Detection surface:** RWX allocation → thread start from non-image memory region
**Source:** `implant/sliver/taskrunner/task_windows.go:LocalTask`

---

### V2 — execute-assembly (in-memory .NET)

**Mechanism:** Load CLR in-process via CorBindToRuntimeEx → invoke assembly entry point from memory

**Command:**
```
execute-assembly <assembly.exe> [args]
```

No disk write. CLR loaded into the implant process memory. Before execution: patchAmsi() + patchEtw().

**Loading target:** `WNetHelper-default.exe` (.NET 4.8, discovery tool — collects local system info, writes output to file)
- Path: `discovery-loading-target/bin/Release/WNetHelper-default.exe`
- Writes output to `%LOCALAPPDATA%\wnet-<timestamp>.log` — easy to verify successful execution

**Detection surface:** CLR loaded into a non-.NET host process, AMSI event
**Source:** `implant/sliver/taskrunner/task_windows.go:InProcExecuteAssembly`

---

### V3 — execute-bof (Beacon Object File)

**Mechanism:** Load COFF object file into implant process memory → resolve Beacon API symbols via Reflektor → execute in-process

**Command:**
```
execute-bof <bof.o> [args]
```

Runs within the implant process memory; does not spawn a new process. BOF format is Cobalt Strike-compatible.

**Loading target:** `wnet-bof.o` + `extension.json`
- Path: `discovery-loading-target/`

**Setup (once per client session):**
```
sliver > extensions load <path-to-discovery-loading-target/>
```

**Command:**
```
sliver (session) > wnet-bof
```

Output returned via Beacon API. Also writes `%LOCALAPPDATA%\wnet-bof.log`.

**Detection surface:** COFF object parsed in-memory, Beacon API shimmed, Reflektor executor
**Source:** `implant/sliver/handlers/handlers_bof.go:executeBOFWithLoader`

---

## Atomic Red Team (no Sliver session required)

### V4 — PowerSploit Reflective DLL Loading

**ART ID:** T1620 Atomic Test #2 (`114c2b95-d992-4c03-8c38-fc58420a3eb5`)

**Mechanism:** PowerShell script parses PE headers → VirtualAlloc → map sections → resolve imports → call DllMain(DLL_PROCESS_ATTACH) → call exported function (`VoidFunc`). Full PE loading implemented in PowerShell without calling LoadLibrary.

**Command:**
```powershell
Import-Module Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEPath wnet-discovery.dll -ForceASLR
```

**Loading target:** `wnet-discovery.dll` (native x64, exports `VoidFunc`)
- Path: `discovery-loading-target/wnet-discovery.dll`
- Log: `%LOCALAPPDATA%\wnet-dll.log`

**Detection surface:** PowerShell script block logging, in-memory PE section mapping, VirtualAlloc from PowerShell, DllMain call via GetDelegateForFunctionPointer
**Note:** Script must be staged locally first. The DLL path allows returning data via exported function and supports remote injection into another process.

---

### V5 — Turla Mosquito EAT Patching

**ART ID:** T1620 Atomic Test #3 (`7c3e0b89-09e6-4f3c-a1e8-1c1dfa9288ce`)

**Mechanism:** DLL self-patches its Export Address Table in memory during DllMain. Fabricates an IMAGE_EXPORT_DIRECTORY in-memory, patches the PE header data-directory entry — hides the real entry point from static analysis.

**Command:**
```powershell
Add-Type -MemberDefinition @'
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr LoadLibraryA(string lpFileName);
'@ -Name "Win32" -Namespace "EATTest" -PassThru | Out-Null
[EATTest.Win32]::LoadLibraryA("CommanderDLL.dll")
```

**Loading target:** `CommanderDLL.dll` (modified — discovery logic added to DllMain)
- Path: `art-scripts/CommanderDLL.dll`
- Log: `%LOCALAPPDATA%\commander-dll.log`

**Detection surface:** `VirtualProtect(PAGE_READWRITE)` on PE header region, EAT mismatch between on-disk and in-memory module, PowerShell script block logging
**Note:** Fundamentally different from V1-V4 — does not load new code but manipulates the PE structure of already-loaded code. Discovery runs inside DllMain immediately on load.
**Source:** `art-scripts/CommanderDLL.c` (modified from `atomic-red-team/atomics/T1620/src/CommanderDll.c`)

---

## Quick Comparison

| Case | Loader | Input | Requires Sliver? | Loading target |
|---|---|---|---|---|
| V1 | Native (VirtualAlloc + CreateThread) | Shellcode .bin | Yes | WNetHelper-default.exe (auto Donut) |
| V2 | CLR hosting | .NET exe/dll | Yes | WNetHelper-default.exe |
| V3 | COFF loader (Reflektor) | BOF .o | Yes | wnet-bof.o |
| V4 | PowerShell PE loader (DLL path) | Native DLL | No | wnet-discovery.dll |
| V5 | Self-patching DLL (EAT) | DLL | No | CommanderDLL.dll (ART) |
