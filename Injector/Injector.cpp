#include <Windows.h>
#include <wtsapi32.h>
#include <string_view>
#include <cwchar>
#include <cwctype>
#include <iostream>
#include <cstring>
#include <vector>
#include <psapi.h>
#include <optional>
#include <spdlog/spdlog.h>
#include <detours/detours.h>

#include "includes/config.h"
#include "includes/injector.h"
#pragma comment(lib, "Wtsapi32.lib")

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

                WTSFreeMemory(pProcessInfo);
                return pProcessInfo[i].ProcessId;
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

        HMODULE hDll = LoadLibraryA(dll64Path.data());
        if (!hDll) {
            std::cerr << "LoadLibraryA failed: " << GetLastError() << '\n';
            return 0;
        }
        FARPROC initHooks{ GetProcAddress(hDll, functionName.data()) };
        if (!initHooks) {
            std::cerr << "GetProcAddress failed for initHooks with error: " << GetLastError() << '\n';
            FreeLibrary(hDll);
            return 0;
        }
        FreeLibrary(hDll);
        uintptr_t delta64 = reinterpret_cast<uintptr_t>(initHooks) - reinterpret_cast<uintptr_t>(hDll);
        return delta64;
    }

    uintptr_t getDelta32(std::string_view dll32Path, std::string_view functionName) {
        //TODO: verify thing is a 32 bit dll
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

        PUINT32 nameArray = reinterpret_cast<PUINT32>(base + exportTable->AddressOfNames);
        bool foundFunction = false;
        UINT32 index{ 0 };

        //TODO: Use binary search
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

            spdlog::error("[Injector] EnumProcessModulesEx failed (get size): {}", GetLastError());

            return NULL;
        }
        if (sizeNeeded == 0) return NULL;

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
        return NULL;
    }


    

}
namespace Injector {


    std::optional<Injector> Injector::get(const Config::Config& config) {

        constexpr std::string_view kernel32DLL{ "C:\\WINDOWS\\System32\\KERNEL32.DLL" };
        constexpr std::string_view woWKernel32DLL{ "C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL" };
        constexpr std::string_view loadLibraryName{ "LoadLibraryA" };

        uintptr_t loadLibraryDelta64 = getDelta64(kernel32DLL.data(), loadLibraryName);
        uintptr_t loadLibraryDelta32 = getDelta32(woWKernel32DLL.data(), loadLibraryName);

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

        auto bitness = getProcessBitType(hProcess);

        if (bitness == Bitness::BIT_INVALID) {
            spdlog::error("[Injector] Invalid/Unsupported architecture found");
            CloseHandle(hProcess);
            return false;
        }

        const ProcConsts* const pProcConst{ (bitness == Bitness::BIT_32)? &proc32 : &proc64 };

        LPVOID writtenAddress = VirtualAllocEx(hProcess, NULL, pProcConst->dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!writtenAddress) {
            spdlog::error("[Injector] Allocating memory in target failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }

        SIZE_T writtenBytes{ 0 };
        BOOL writeProcessMemory = WriteProcessMemory(hProcess, writtenAddress, pProcConst->dllPath.data(), pProcConst->dllPath.length() + 1, &writtenBytes);
        if (!writeProcessMemory || (writtenBytes < (pProcConst->dllPath.length() + 1))) {
            spdlog::error("[Injector] Writing in target's memory failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }

        uintptr_t loadLibraryAddress{ reinterpret_cast<uintptr_t>(getModuleHandle("KERNEL32.DLL", hProcess, bitness)) + pProcConst->loadLibraryDelta };
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), writtenAddress, 0, NULL);
        if (!hThread) {
            spdlog::error("[Injector] LoadLibrary thread creation failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        uintptr_t initHooksAddress{ reinterpret_cast<uintptr_t>(getModuleHandle(pProcConst->dllPath, hProcess, bitness)) + pProcConst->calleeDelta };
        if (!initHooksAddress) {
            spdlog::error("[Injector] Failed to retrieve callee delta in target");
            return false;
        }

        HANDLE hInitThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(initHooksAddress), NULL, 0, NULL);
        if (!hInitThread) {
            spdlog::error("[Injector] Invloking callee failed with: {}", GetLastError());
            CloseHandle(hProcess);
            return false;
        }
        WaitForSingleObject(hInitThread, INFINITE);
        CloseHandle(hInitThread);

        CloseHandle(hProcess);

        spdlog::info("Successfully injected");
        return true;
    }
    void Injector::modeOnce() {
        for (auto pid : config.processIDs) {
            injectPID(pid);
        }

        for (const auto& processCmd : config.processName) {
            auto position = processCmd.find(" ");

            auto pid = getProcessID((position != std::string::npos) ? processCmd.substr(0, position) : processCmd);

            injectPID(pid);
            
        }

    }

    void Injector::modeCreate() {

        for (const auto& processCmd : config.processName) {
            
            STARTUPINFOA stInfo{};
            PROCESS_INFORMATION procInfo{};

            std::vector<char> cmdLine(processCmd.begin(), processCmd.end());

            if (DetourCreateProcessWithDllExA(
                NULL,
                cmdLine.data(),
                NULL,
                NULL,
                FALSE,
                0,
                NULL,
                NULL,
                &stInfo,
                &procInfo,
                config.pathStartupDll.c_str(),
                NULL
            )) {
                spdlog::warn("[Injector] Invalid injector mode received");
            }

            WaitForSingleObject(procInfo.hProcess, INFINITE);
            CloseHandle(procInfo.hProcess);
            CloseHandle(procInfo.hThread);

            spdlog::info("[Injector] Created and injected into process{}", processCmd);

        }

    }


    bool Injector::run() {

        switch (config.injectorMode) {

        case Config::InjectorMode::INJECT_ONCE:
            modeOnce();
            break;

        case Config::InjectorMode::INJECT_CREATE:
            modeCreate();
            break;

        default:
            spdlog::error("[Injector] Invalid injector mode received");
            return false;

        }

        return true;

    }

}