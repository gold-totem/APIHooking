#include <spdlog/fmt/fmt.h>
//#define SPDLOG_WCHAR_TO_UTF8_SUPPORT

#include <phnt_windows.h>
#include <phnt.h>

#include "detours/detours.h"
#include "includes/hooking.h"

#define CREATE_HOOK(functionName) \
	{ \
		auto procAddress{ GetProcAddress(hNtdll, #functionName) }; \
		if(procAddress == NULL ){ \
			SPDLOG_ERROR("[Hook] Couldn't find {} in ntdll", #functionName); \
			return false; \
		}\
		TrueFuncPtrs::true##functionName = reinterpret_cast<p##functionName>( procAddress ); \
	}

#define ATTACH_HOOK(functionName) \
	isError |= DetourAttach(&(reinterpret_cast<PVOID&>(TrueFuncPtrs::true##functionName)), DetouredFunc::det##functionName)
	


namespace {

	std::shared_ptr<spdlog::logger> sensor{ nullptr };

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
			if (!sensor) { 
				if(Monitor::initLogger()) sensor->info("LdrLoadDll, DllPath:{}", fmt::ptr(DllName->Buffer));
			}			
			return TrueFuncPtrs::trueLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
		}
	}
}

namespace Monitor {
	bool createHooks() {

		SPDLOG_INFO("[Hook] createHooks called.");


		sensor = spdlog::get("Sensor");

		if (!sensor) {
			SPDLOG_ERROR("[Hook] Couldn't retrive logger");
			return false;
		}
		SPDLOG_INFO("[Hook] createHooks called.");

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (!hNtdll) {
			SPDLOG_ERROR("[Hook] Getting handle to ntdll failed with: {}", GetLastError());
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

