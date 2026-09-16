#include <Windows.h>
#include <wtsapi32.h>
#include <psapi.h>
#include <userenv.h>

#include <string_view>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <vector>
#include <optional>

#include <spdlog/spdlog.h>
#include <detours/detours.h>
#include "includes/config.h"
#include "includes/injector.h"

namespace {
    

    using pInitHooks = bool(__cdecl*)();
    enum class Bitness {
        BIT_64,
        BIT_32,
        BIT_INVALID
    };

    DWORD getProcessID(std::string_view processName) {

        PWTS_PROCESS_INFOA pProcessInfo{ nullptr };
        DWORD count{ 0 };
        if (!WTSEnumerateProcessesA(
            WTS_CURRENT_SERVER_HANDLE,
            NULL,
            1,
            &pProcessInfo,
            &count
        )) {
            spdlog::error("[Injector] Process enumeration failed");
            return 0;
        }
        for (DWORD i{ 0 }; i < count; i++) {

            if (_stricmp(processName.data(), pProcessInfo[i].pProcessName) == 0) {
                auto pid{ pProcessInfo[i].ProcessId };
                WTSFreeMemory(pProcessInfo);
                return pid;
            }
        }

        WTSFreeMemory(pProcessInfo);

        return 0;
    }
    Bitness getProcessBitType(HANDLE hProcess) {
        if (!hProcess) {
            spdlog::error("[Injector] Invalid process Handle recived");
            return Bitness::BIT_INVALID;
        }
        USHORT processMachine{ 0 };
        USHORT nativeMachine{ 0 };
        if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine)) {

            spdlog::error("[Injector] Could not retrive bitness of target process: {}", GetLastError());
            return Bitness::BIT_INVALID;
        }
        if (nativeMachine != IMAGE_FILE_MACHINE_AMD64) {
            spdlog::error("[Injector] Invalid native machine type detected");
            return Bitness::BIT_INVALID;
        }
        if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
            return Bitness::BIT_64;
        }
        return Bitness::BIT_32;
    }

    uintptr_t getDelta64(std::string_view dll64Path, std::string_view functionName) {
        //TODO: PE parsing for 64 bit too
        HMODULE hDll = LoadLibraryA(dll64Path.data());
        if (!hDll) {
            spdlog::error("[Injector] LoadLibraryA failed with{}",GetLastError());
            return 0;
        }
        FARPROC initHooks{ GetProcAddress(hDll, functionName.data()) };
        if (!initHooks) {
            spdlog::error("[Injector] GetProcAddress failed for initHooks with error {}", GetLastError());
            FreeLibrary(hDll);
            return 0;
        }
        FreeLibrary(hDll);
        uintptr_t delta64 = reinterpret_cast<uintptr_t>(initHooks) - reinterpret_cast<uintptr_t>(hDll);
        return delta64;
    }

    uintptr_t getDelta32(std::string_view dll32Path, std::string_view functionName) {

        HANDLE hDLLFile = CreateFileA(dll32Path.data(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDLLFile == INVALID_HANDLE_VALUE) {

            spdlog::error("[Injector] Invalid handle returned");
            return 0;
        }
        HANDLE hMapping = CreateFileMappingA(hDLLFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        if (!hMapping) {

            spdlog::error("[Injector] File mapping failed with: {}", GetLastError());

            CloseHandle(hDLLFile);
            return 0;
        }
        BYTE* base = reinterpret_cast<BYTE*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
        if (!base) {
            
            spdlog::error("[Injector] Mapping view failed with: {}", GetLastError());
            CloseHandle(hDLLFile);
            CloseHandle(hMapping);
            return 0;
        }

        IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        IMAGE_NT_HEADERS32* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dosHeader->e_lfanew);
        IMAGE_OPTIONAL_HEADER32* optionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&(ntHeader->OptionalHeader));
        IMAGE_EXPORT_DIRECTORY* exportTable = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        const WORD* bitType = reinterpret_cast<WORD*>(&(optionalHeader));

        if (*bitType !=  IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            spdlog::error("[Injector] Provided 32-bit DLL in not 32-bit");
            return 0;
        }


        PUINT32 nameArray = reinterpret_cast<PUINT32>(base + exportTable->AddressOfNames);
        bool foundFunction = false;
        UINT32 index{ 0 };

        for (UINT32 i = 0; i < exportTable->NumberOfNames; i++) {
            UINT32 nameRVA = nameArray[i];
            char* funcName = (char*)(base + nameRVA);
            if (std::strcmp(functionName.data(), funcName) == 0) {
                foundFunction = true;
                index = i;
            }
        }
        if (!foundFunction) {
            spdlog::error("[Injector] Function: {} not found in {}", functionName, dll32Path);

            UnmapViewOfFile(base);
            CloseHandle(hMapping);
            CloseHandle(hDLLFile);
            return 0;
        }

        PUINT16 ordinalTable = reinterpret_cast<PUINT16>(base + exportTable->AddressOfNameOrdinals);
        DWORD* exportAddressTable = reinterpret_cast<DWORD*>(base + exportTable->AddressOfFunctions);
        DWORD ordinal = ordinalTable[index];
        uintptr_t offset = static_cast<uintptr_t>(exportAddressTable[ordinal]);

        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hDLLFile);

        return offset;
    }

    HMODULE getModuleHandle(std::string_view moduleName, HANDLE hProcess, const Bitness& bitness) {
        DWORD flags = LIST_MODULES_64BIT;
        if (bitness == Bitness::BIT_32) flags = LIST_MODULES_32BIT;

        DWORD sizeNeeded = 0;
        if (!EnumProcessModulesEx(hProcess, nullptr, 0, &sizeNeeded, flags)) {
            spdlog::error("EnumProcessModulesEx retrive: {}", GetLastError());
        }

        if (sizeNeeded == 0) { 
            spdlog::error("Couldn't retrive required buffer size to enumerate modules for {}", moduleName);
            return NULL;
        }

        size_t count = sizeNeeded / sizeof(HMODULE);
        std::vector<HMODULE> modules(count);
        DWORD bytesReturned = 0;
        if (!EnumProcessModulesEx(hProcess, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &bytesReturned, flags)) {
            spdlog::error("[Injector] EnumProcessModulesEx failed (retrieve): {}", GetLastError());

            return NULL;
        }
        size_t numReturned = bytesReturned / sizeof(HMODULE);
        constexpr DWORD nameBufLen = 4096;
        std::string moduleNameStr(moduleName);

        for (size_t i = 0; i < numReturned; ++i) {
            char nameBuf[nameBufLen] = { 0 };
            if (!GetModuleBaseNameA(hProcess, modules[i], nameBuf, nameBufLen)) {
                continue;
            }
            if (moduleNameStr == nameBuf) {
                return modules[i];
            }
        }
        spdlog::error("Could not find module {} in the target process", moduleName);
        return NULL;
    }

    std::string expandEnv(std::string_view envVar) {

    }
    

}
namespace Injector {


    std::optional<Injector> Injector::get(const Config::Config& config) {


        char path[MAX_PATH];

        memset(path, 0, sizeof(path));

        if (!ExpandEnvironmentStringsForUserA(
            NULL,
            "%WINDIR%",
            path,
            sizeof(path)
        )) {
            spdlog::error("[Injector] Error expanding %WINDIR%");
            return std::nullopt;
        }

        std::string kernel32DLL{ path };
        kernel32DLL += "\\System32\\KERNEL32.DLL";

        std::string woWKernel32DLL{ path };
        woWKernel32DLL += "\\SysWOW64\\KERNEL32.DLL";
    
        constexpr std::string_view loadLibraryName{ "LoadLibraryA" };

        uintptr_t loadLibraryDelta64 = getDelta64( kernel32DLL, loadLibraryName);
        uintptr_t loadLibraryDelta32 = getDelta32(woWKernel32DLL, loadLibraryName);

        if (!loadLibraryDelta32 || !loadLibraryDelta64) {
            spdlog::error("[Injector] Error retrieving LoadLibraryA delta");
            return std::nullopt;
        }

        uintptr_t calleeDelta64 = getDelta64(config.path64, config.calleeName);
        uintptr_t calleeDelta32 = getDelta32(config.path32, config.calleeName);

        if (!calleeDelta64 || !calleeDelta32) {
            spdlog::error("[Injector] Error retrieving callee delta");
            return std::nullopt;
        }

        ProcConsts p64{ config.path64 , calleeDelta64, loadLibraryDelta64 };

        ProcConsts p32{ config.path32 , calleeDelta32, loadLibraryDelta32 };

        return Injector(p64, p32, config);
    }

    bool Injector::injectPID(DWORD pid) {


        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            spdlog::error("[Injector] Opening target failed with: {}", GetLastError());
            return false;
        }
        spdlog::info("[Injector] Target process opened successfully");

        auto bitness = getProcessBitType(hProcess);

        if (bitness == Bitness::BIT_INVALID) {
            spdlog::error("[Injector] Invalid/Unsupported architecture found");
            CloseHandle(hProcess);
            return false;
        }

        const ProcConsts& pProcConst{ (bitness == Bitness::BIT_32)? proc32 : proc64 };

        LPVOID writtenAddress = VirtualAllocEx(hProcess, NULL, pProcConst.dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!writtenAddress) {
            spdlog::error("[Injector] Allocating memory in target failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }

        spdlog::info("[Injector] Allocated memory in target process successfully");

        SIZE_T writtenBytes{ 0 };
        BOOL writeProcessMemory = WriteProcessMemory(hProcess, writtenAddress, pProcConst.dllPath.data(), pProcConst.dllPath.length() + 1, &writtenBytes);
        if (!writeProcessMemory || (writtenBytes < (pProcConst.dllPath.length() + 1))) {
            spdlog::error("[Injector] Writing in target's memory failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }

        spdlog::info("[Injector] Wrote into target process successfully");

        auto hKernel32{getModuleHandle("KERNEL32.DLL", hProcess, bitness)};

        if (hKernel32 == NULL) {
            CloseHandle(hProcess);
            return false;
        }
        uintptr_t loadLibraryAddress{ reinterpret_cast<uintptr_t>(hKernel32) + pProcConst.loadLibraryDelta };
        
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), writtenAddress, 0, NULL);
        if (!hThread) {
            spdlog::error("[Injector] LoadLibrary thread creation failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }

        spdlog::info("[Injector] Called LoadLibrary successfully");

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);


        auto hDll{ getModuleHandle(pProcConst.dllPath.substr(pProcConst.dllPath.find_last_of('\\') + 1), hProcess, bitness)};

        if (hDll == NULL) {
            CloseHandle(hProcess);
            return false;
        }


        uintptr_t initHooksAddress{ reinterpret_cast<uintptr_t>(hDll) + pProcConst.calleeDelta };
        if (!initHooksAddress) {
            spdlog::error("[Injector] Failed to retrieve callee delta in target");
            return false;
        }

        HANDLE hInitThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(initHooksAddress), NULL, 0, NULL);
        if (!hInitThread) {
            spdlog::error("[Injector] Invoking callee failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }


        spdlog::info("[Injector] Called {} successfully", config.calleeName);

        WaitForSingleObject(hInitThread, INFINITE);
        CloseHandle(hInitThread);

        CloseHandle(hProcess);

        spdlog::info("Successfully injected");
        return true;

    }


    bool Injector::run() {

        spdlog::info("[Injector] running injector");

        for (auto pid : config.processIDs) {
            injectPID(pid);
        }

        for (const auto& processCmd : config.processNames) {
            auto position = processCmd.find(" ");

            auto pid = getProcessID((position != std::string::npos) ? processCmd.substr(0, position) : processCmd);

            if (!pid) {
                spdlog::warn("[Injector] No process found for the command: {}", processCmd);
                continue;
            }

            injectPID(pid);

        }

        return true;

    }

}