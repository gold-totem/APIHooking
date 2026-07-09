#include <Windows.h>
#include <Psapi.h>
#include <wtsapi32.h>

#include <string_view>
#include <cwchar>
#include <cwctype>
#include <iostream>
#include <cstring>
#include <vector>

#pragma comment(lib, "Wtsapi32.lib")

namespace {

    using pInitHooks = bool(__cdecl*)();

    struct Constants {
        const std::string dllName;
        const std::string monitorDLLPath64;
        const std::string monitorDLLPath32;
        const std::string functionName;

        Constants(
            std::string dllName, std::string m64, std::string m32, std::string funcName
        ) :
            dllName{ std::move(dllName) },
            monitorDLLPath64{ std::move(m64) },
            monitorDLLPath32{ std::move(m32) },
            functionName{ std::move(funcName) }
        {
        }

    };
    enum class Bitness {
        BIT_64,
        BIT_32,
        BIT_INVALID
    };
    struct ProcConsts {
        const std::string_view monitorDLLPath;
        const std::string dllName;
        const uintptr_t hookingFuncDelta;
        const uintptr_t loadLibraryDelta;
        const SIZE_T sizeOfdllPath;

        ProcConsts(std::string_view dllPath,
            std::string dllN,
            uintptr_t hookDelta,
            uintptr_t loadDelta
        ) :
            monitorDLLPath{ dllPath },
            dllName{ dllN },
            hookingFuncDelta{ hookDelta },
            loadLibraryDelta{ loadDelta },
            sizeOfdllPath{ (dllPath.length() + 1) * sizeof(char) }
        {
        }
    };

    struct ProcInfo {
        HANDLE hProcess{ NULL };
        enum Bitness bitness;
        const ProcConsts* pProcConst;

    };

    HANDLE getProcessHandle(std::wstring_view processName) {
        PWTS_PROCESS_INFO pProcessInfo{ nullptr };
        DWORD count{ 0 };
        if (!WTSEnumerateProcessesW(
            WTS_CURRENT_SERVER_HANDLE,
            NULL,
            1,
            &pProcessInfo,
            &count
        )) {
            std::wcerr << L"WTSEnumerateProcessesW failed: " << GetLastError() << 'L\n';
            return INVALID_HANDLE_VALUE;
        }
        for (DWORD i{ 0 }; i < count; i++) {

            if (_wcsicmp(processName.data(), pProcessInfo[i].pProcessName) == 0) {

                HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProcessInfo[i].ProcessId);

                if (!hProc) {
                    std::wcerr << "OpenProcess failed: " << GetLastError();
                }
                return hProc;
            }
        }

        WTSFreeMemory(pProcessInfo);

        return INVALID_HANDLE_VALUE;
    }
    Bitness getProcessBitType(HANDLE hProcess) {
        if (!hProcess) {
            std::cerr << "Invalid process Handle recived";
            return Bitness::BIT_INVALID;
        }
        USHORT processMachine{ 0 };
        USHORT nativeMachine{ 0 };
        if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
            std::cerr << "Could not retrive bitness of target process: " << GetLastError();
            return Bitness::BIT_INVALID;
        }
        if (nativeMachine != IMAGE_FILE_MACHINE_AMD64) {
            std::cerr << "Invalid native machine type detected";
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
            std::cerr << "Invalid handle returned: " << GetLastError() << '\n';
            return 0;
        }
        HANDLE hMapping = CreateFileMappingA(hDLLFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        if (!hMapping) {
            std::cerr << "CreateFileMappingA failed: " << GetLastError() << '\n';
            CloseHandle(hDLLFile);
            return 0;
        }
        BYTE* base = reinterpret_cast<BYTE*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
        if (!base) {
            std::cerr << "MapViewOfFile failed: " << GetLastError() << '\n';
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
            std::cerr << "Function: " << functionName << " not found in: " << dll32Path << std::endl;
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
            std::cerr << "EnumProcessModulesEx failed (get size): " << GetLastError() << "\n";
            return NULL;
        }
        if (sizeNeeded == 0) return NULL;

        size_t count = sizeNeeded / sizeof(HMODULE);
        std::vector<HMODULE> modules(count);
        DWORD bytesReturned = 0;
        if (!EnumProcessModulesEx(hProcess, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &bytesReturned, flags)) {
            std::cerr << "EnumProcessModulesEx failed (retrieve): " << GetLastError() << "\n";
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

int main(int argc, char* argv[]) {

    //TODO: take these from a config file or something
    constexpr std::string_view dllName{ "monitor" };
    constexpr std::string_view dll64Path{ "D:\\workspace\\VSRepos\\Learning\\DetoursTest\\x64\\Release\\monitor64.dll" };
    constexpr std::string_view dll32Path{ "D:\\workspace\\VSRepos\\Learning\\DetoursTest\\Release\\monitor32.dll" };
    constexpr std::string_view functionName{ "initHooks" };

    const struct Constants constants {
        dllName.data(),
            dll64Path.data(),
            dll32Path.data(),
            functionName.data()
    };

    constexpr std::string_view kernel32DLL = "C:\\WINDOWS\\System32\\KERNEL32.DLL";
    constexpr std::string_view woWKernel32DLL = "C:\\WINDOWS\\SysWOW64\\KERNEL32.DLL";
    constexpr std::string_view loadLibraryName = "LoadLibraryA";

    uintptr_t initHooksDelta64 = getDelta64(dll64Path.data(), functionName.data());
    uintptr_t initHooksDelta32 = getDelta32(dll32Path.data(), functionName.data());

    uintptr_t loadLibraryDelta64 = getDelta64(kernel32DLL.data(), loadLibraryName);
    uintptr_t loadLibraryDelta32 = getDelta32(woWKernel32DLL.data(), loadLibraryName);

    const struct ProcConsts procConsts64 {
        constants.monitorDLLPath64,
            constants.dllName + "64.dll",
            initHooksDelta64,
            loadLibraryDelta64
    };

    const struct ProcConsts procConsts32 {
        constants.monitorDLLPath32,
            constants.dllName + "32.dll",
            initHooksDelta32,
            loadLibraryDelta32
    };
    struct ProcInfo procInfo { 0 };

    procInfo.hProcess = getProcessHandle(L"Target.exe");
    if (!procInfo.hProcess) {
        std::cerr << "Open Process failed: " << GetLastError();
        return 1;
    }

    procInfo.bitness = getProcessBitType(procInfo.hProcess);
    if (procInfo.bitness == Bitness::BIT_INVALID) {
        std::cerr << "Invalid Bit type found." << std::endl;
        CloseHandle(procInfo.hProcess);
        return 1;
    }

    if (procInfo.bitness == Bitness::BIT_32) {
        procInfo.pProcConst = &procConsts32;
    }
    else {
        procInfo.pProcConst = &procConsts64;
    }

    LPVOID writtenAddress = VirtualAllocEx(procInfo.hProcess, NULL, procInfo.pProcConst->sizeOfdllPath, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!writtenAddress) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError();
        CloseHandle(procInfo.hProcess);
        return 1;
    }

    SIZE_T writtenBytes{ 0 };
    BOOL writeProcessMemory = WriteProcessMemory(procInfo.hProcess, writtenAddress, procInfo.pProcConst->monitorDLLPath.data(), procInfo.pProcConst->sizeOfdllPath, &writtenBytes);
    if (!writeProcessMemory || (writtenBytes < procInfo.pProcConst->sizeOfdllPath)) {
        std::cout << "WriteProcessMemory Failed: " << GetLastError();
        CloseHandle(procInfo.hProcess);
        return 1;
    }

    uintptr_t loadLibraryAddress{ reinterpret_cast<uintptr_t>(getModuleHandle("KERNEL32.DLL", procInfo.hProcess, procInfo.bitness)) + procInfo.pProcConst->loadLibraryDelta };
    HANDLE hThread = CreateRemoteThread(procInfo.hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), writtenAddress, 0, NULL);
    if (!hThread) {
        std::cerr << "Thread Creation for LoadLibraryA failed: " << GetLastError();
        CloseHandle(procInfo.hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    uintptr_t initHooksAddress{ reinterpret_cast<uintptr_t>(getModuleHandle(procInfo.pProcConst->dllName, procInfo.hProcess, procInfo.bitness)) + procInfo.pProcConst->hookingFuncDelta };
    if (!initHooksAddress) {
        std::cerr << "Could not get initHooks address\n";
        return 1;
    }

    HANDLE hInitThread = CreateRemoteThread(procInfo.hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(initHooksAddress), NULL, 0, NULL);
    if (!hInitThread) {
        std::cerr << "Thread Creation for initHooksAddress failed: " << GetLastError();
        CloseHandle(procInfo.hProcess);
        return 1;
    }
    WaitForSingleObject(hInitThread, INFINITE);
    CloseHandle(hInitThread);
    std::cout << "successfully injected";
    CloseHandle(procInfo.hProcess);
}