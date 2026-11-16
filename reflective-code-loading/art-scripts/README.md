# art-scripts

| File | Purpose |
|---|---|
| `Invoke-ReflectivePEInjection.ps1` | PowerSploit PE loader (patched for PS 5.1). Load: `Import-Module .\Invoke-ReflectivePEInjection.ps1` then `Invoke-ReflectivePEInjection -PEPath ..\discovery-loading-target\wnet-discovery.dll -ForceASLR` |
| `CommanderDLL.dll` | EAT patching DLL. Load via `LoadLibraryA` in a fresh PS session. Writes discovery output to `%LOCALAPPDATA%\commander-dll.log` |
| `CommanderDLL.c` | Source for CommanderDLL.dll |
