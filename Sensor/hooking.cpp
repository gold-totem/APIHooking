#include <phnt_windows.h>
#include <phnt.h>

#include "detours/detours.h"
#include "includes/hooking.h"

#define CREATE_HOOK(functionName) \
	{ \
		auto procAddress{ GetProcAddress(hNtdll, #functionName) }; \
		if(procAddress == NULL ) return false; \
		TrueFuncPtrs::true##functionName = reinterpret_cast<p##functionName>( procAddress ); \
	}

#define ATTACH_HOOK(functionName) \
	isError |= DetourAttach(&(reinterpret_cast<PVOID&>(TrueFuncPtrs::true##functionName)), DetouredFunc::det##functionName)
	


namespace {

	auto sensor = spdlog::get("Sensor");

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
			if (sensor) sensor->info("LdrLoadDll");
			
			return TrueFuncPtrs::trueLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
		}
	}
}

namespace Monitor {
	bool createHooks() {

		SPDLOG_INFO("[Hook] createHooks called.");

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (!hNtdll) {
			SPDLOG_ERROR("Getting handle to ntdll failed with: {}", GetLastError());
			return false;
		}

		SPDLOG_INFO("[Hook] Retrieved ntdll handle.");

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

