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

	using pNtAllocateVirtualMemoryEx = NTSTATUS
		(NTAPI*)
		(
			_In_ HANDLE ProcessHandle,
			_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
			_Inout_ PSIZE_T RegionSize,
			_In_ ULONG AllocationType,
			_In_ ULONG PageProtection,
			_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
			_In_ ULONG ExtendedParameterCount
		);
	using pNtWriteVirtualMemory = NTSTATUS
		(NTAPI*)
		(
			_In_ HANDLE ProcessHandle,
			_In_opt_ PVOID BaseAddress,
			_In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
			_In_ SIZE_T NumberOfBytesToWrite,
			_Out_opt_ PSIZE_T NumberOfBytesWritten
		);
	namespace TrueFuncPtrs {
		pLdrLoadDll trueLdrLoadDll{ nullptr };
		pNtOpenProcess trueNtOpenProcess{ nullptr };
		pNtAllocateVirtualMemoryEx trueNtAllocateVirtualMemoryEx{ nullptr };
		pNtWriteVirtualMemory trueNtWriteVirtualMemory{ nullptr };
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
				if (ClientId && ClientId->UniqueProcess) sensor->info("NtOpenProcess, PID: {}", *(reinterpret_cast<DWORD*>(ClientId->UniqueProcess)));
				else sensor->info("NtOpenProcess");
			}
			return TrueFuncPtrs::trueNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

		}


		NTSTATUS
			NTAPI
			detNtAllocateVirtualMemoryEx(
				_In_ HANDLE ProcessHandle,
				_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
				_Inout_ PSIZE_T RegionSize,
				_In_ ULONG AllocationType,
				_In_ ULONG PageProtection,
				_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
				_In_ ULONG ExtendedParameterCount
			) {
			if (sensor) {
				sensor->info("NtAllocateVirtualMemoryEx, PID: {}", GetProcessId(ProcessHandle));
			}
			return TrueFuncPtrs::trueNtAllocateVirtualMemoryEx(ProcessHandle, BaseAddress, RegionSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount);
		}

		NTSTATUS
			NTAPI
			detNtWriteVirtualMemory(
				_In_ HANDLE ProcessHandle,
				_In_opt_ PVOID BaseAddress,
				_In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
				_In_ SIZE_T NumberOfBytesToWrite,
				_Out_opt_ PSIZE_T NumberOfBytesWritten
			) {
			if (sensor) {
				sensor->info("NtWriteVirtualMemory, PID: {}", GetProcessId(ProcessHandle));
			}
			return TrueFuncPtrs::trueNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
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

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (!hNtdll) {
			SPDLOG_ERROR("[Hook] Getting handle to ntdll failed with: {}", GetLastError());
			return false;
		}

		SPDLOG_INFO("[Hook] Retrieved ntdll handle.");

		CREATE_HOOK(LdrLoadDll);
		CREATE_HOOK(NtOpenProcess);
		CREATE_HOOK(NtAllocateVirtualMemoryEx)
		CREATE_HOOK(NtWriteVirtualMemory);

		SPDLOG_INFO("[Hook] Hooks Created");
		return true;

	}

	bool attachHooks() {
		bool isError{ false };

		ATTACH_HOOK(LdrLoadDll);
		ATTACH_HOOK(NtOpenProcess);
		ATTACH_HOOK(NtAllocateVirtualMemoryEx);
		ATTACH_HOOK(NtWriteVirtualMemory);

		return !isError;
	}
}

