#include <phnt_windows.h>
#include <phnt.h>


#include "detours/detours.h"

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include "spdlog/spdlog.h"
#include "includes/hooking.h"

#define CREATE_HOOK(functionName) \
	TrueFuncPtrs::true##functionName = reinterpret_cast<p##functionName>(GetProcAddress(hNtdll, #functionName));

#define ATTACH_HOOK(functionName) \
	isError |= DetourAttach(&(reinterpret_cast<PVOID&>(TrueFuncPtrs::true##functionName)), DetouredFunc::det##functionName)
	


namespace {
	using pLdrLoadDll = NTSTATUS
		(NTAPI*)
		(
			_In_opt_ PCWSTR DllPath,
			_In_opt_ PULONG DllCharacteristics,
			_In_ PCUNICODE_STRING DllName,
			_Out_ PVOID* DllHandle
		);

	namespace TrueFuncPtrs {
		pLdrLoadDll trueLdrLoadDll{ nullptr };
	}

	namespace DetouredFunc {
		NTSTATUS NTAPI detLdrLoadDll(
			_In_opt_ PCWSTR DllPath,
			_In_opt_ PULONG DllCharacteristics,
			_In_ PCUNICODE_STRING DllName,
			_Out_ PVOID* DllHandle
		) {
			//log

			return TrueFuncPtrs::trueLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
		}
	}
}

namespace Monitor {
	bool createHooks() {

		SPDLOG_INFO("[Hook] Creating hooks");

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (!hNtdll) {
			SPDLOG_ERROR("Getting handle to ntdll failed with: {}", GetLastError());
			return false;
		}

		CREATE_HOOK(LdrLoadDll);

		SPDLOG_INFO("[Hook] Hooks Created");
		return true;

	}

	bool attachHooks() {
		bool isError{ false };

		ATTACH_HOOK(LdrLoadDll);

		return !isError;
	}
}

