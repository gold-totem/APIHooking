# API Hooking

A simple project demonstrating how security solutions use API hooking to monitor processes.

### Flow

* Injects a "Sensor DLL" into a target process using `CreateRemoteThread` + `LoadLibraryA`
* Injects the corresponding 32/64-bit DLL
* Hooks NT APIs using Detours
* Logs hooked API calls to `%PROGRAMDATA%\APIHooking\`

### Components

* Injector — Reads configuration, locates the target process, and injects the Sensor DLL
* Sensor — Installs Detours hooks and logs API calls

### Requirements

* Visual Studio 2026
* CMake
* vcpkg

### Build

```bash
cmake -B build -G "Visual Studio 18 2026"
cmake --build build --config Release
```

For a 32-bit Sensor:

```bash
cmake -B build32 -G "Visual Studio 18 2026" -A Win32 .
cmake --build build32 --target Sensor --config Release
```

### Usage

```bash
Injector.exe -c <config_path>
```

See `config/config.json` for an example configuration.
