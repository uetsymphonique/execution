# discovery-loading-target

Benign discovery payloads for reflective code loading. All variants collect local system info (hostname, OS, user, processes, services, files) and write output to a log file under `%LOCALAPPDATA%`.

## Targets

| File | Format | Loader |
|---|---|---|
| `WNetHelper-default.exe` | .NET 4.8 EXE | Sliver `execute-shellcode`, `execute-assembly`, PowerSploit (EXE mode) |
| `wnet-discovery.dll` | Native x64 DLL, exports `VoidFunc` | PowerSploit `Invoke-ReflectivePEInjection` (DLL mode) |
| `wnet-bof.o` | COFF object (BOF) | Sliver `extensions load` + `wnet-bof` |

## Build

### WNetHelper-default.exe (.NET 4.8)

```
msbuild WNetHelper-default.csproj /p:Configuration=Release
```

Output: `bin\Release\WNetHelper-default.exe`
Log: `%LOCALAPPDATA%\wnet-<timestamp>.log`

### wnet-discovery.dll (Native x64)

```
cl /LD /Os wnet-dll.c /Fe:wnet-discovery.dll /link kernel32.lib advapi32.lib shlwapi.lib ntdll.lib
```

Exports: `VoidFunc` (no parameters, void return)
Log: `%LOCALAPPDATA%\wnet-dll.log`

### wnet-bof.o (BOF)

```
cl /c /GS- /Os wnet-bof.c /Fo:wnet-bof.o
```

Entry: `go` (Beacon API)
Log: `%LOCALAPPDATA%\wnet-bof.log`
Requires `extension.json` manifest for Sliver `extensions load`.

## Source files

| File | Purpose |
|---|---|
| `Program.cs` | .NET entry point, runs RunLocal() by default |
| `SysCollector.cs` | System info collection logic |
| `NBNSResolver.cs` | NBNS resolver (not used in default mode) |
| `PerfCounter.cs` | Performance counter utilities |
| `wnet-dll.c` | Native DLL version, exports `VoidFunc` |
| `wnet-bof.c` | BOF version, Beacon API output |
| `beacon.h` | Beacon API header for BOF compatibility |
| `extension.json` | Sliver BOF extension manifest |
