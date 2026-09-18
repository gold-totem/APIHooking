#include "includes/hooking.h"

#include <phnt_windows.h>
#include <phnt.h>
#include <spdlog/fmt/fmt.h>
#include "detours/detours.h"

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
	isError |= static_cast<bool>(DetourAttach(&(reinterpret_cast<PVOID&>(TrueFuncPtrs::true##functionName)), DetouredFunc::det##functionName))
	


namespace {
	/* TODO: 
		NtAllocateVirtualMemoryEx()
		NtWriteVirtualMemory()
		NtCreateThreadEx()
		NtQueueApcThread
		NtMapViewOfSection
		NtQueryInformationProcess
		NtSuspendProcess / NtResumeProcess
		NtCreateUserProcess

	*/

	std::shared_ptr<spdlog::logger> sensor{ nullptr };

	using pLdrLoadDll = NTSTATUS
		(NTAPI*)
		(
			_In_opt_ PCWSTR DllPath,
			_In_opt_ PULONG DllCharacteristics,
			_In_ PCUNICODE_STRING DllName,
			_Out_ PVOID* DllHandle
		);

	using pNtOpenProcess = NTSTATUS
		(NTAPI*)
		(
			_Out_ PHANDLE ProcessHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PCLIENT_ID ClientId
		);

	namespace TrueFuncPtrs {
		pLdrLoadDll trueLdrLoadDll{ nullptr };
		pNtOpenProcess trueNtOpenProcess{ nullptr };
	}

	namespace DetouredFunc {

		NTSTATUS NTAPI detLdrLoadDll(
			_In_opt_ PCWSTR DllPath,
			_In_opt_ PULONG DllCharacteristics,
			_In_ PCUNICODE_STRING DllName,
			_Out_ PVOID* DllHandle
		) {
			if (sensor) { 

				std::wstring name(
					DllName->Buffer,
					DllName->Length / sizeof(WCHAR)
				);

				int size = WideCharToMultiByte(
					CP_UTF8,
					0,
					name.data(),
					static_cast<int>(name.size()),
					nullptr,
					0,
					nullptr,
					nullptr
				);

				std::string utf8Name(size, '\0');

				WideCharToMultiByte(
					CP_UTF8,
					0,
					name.data(),
					static_cast<int>(name.size()),
					utf8Name.data(),
					size,
					nullptr,
					nullptr
				);

				sensor->info("LdrLoadDll, DllName: {}", utf8Name);
			}			
			return TrueFuncPtrs::trueLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
		}


		NTSTATUS NTAPI detNtOpenProcess(
				_Out_ PHANDLE ProcessHandle,
				_In_ ACCESS_MASK DesiredAccess,
				_In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
				_In_opt_ PCLIENT_ID ClientId
			) {
			if (sensor) {

				sensor->info("NtOpenProcess, PID: {}", *(reinterpret_cast<DWORD*>(ClientId->UniqueProcess)));
			}
			return TrueFuncPtrs::trueNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

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

