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

	using pNtCreateThreadEx = NTSTATUS
		(NTAPI*)
		(
			_Out_ PHANDLE ThreadHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
			_In_ HANDLE ProcessHandle,
			_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
			_In_opt_ PVOID Argument,
			_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
			_In_ SIZE_T ZeroBits,
			_In_ SIZE_T StackSize,
			_In_ SIZE_T MaximumStackSize,
			_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
		);

	using pNtCreateUserProcess = NTSTATUS
		(NTAPI*)
		(
			_Out_ PHANDLE ProcessHandle,
			_Out_ PHANDLE ThreadHandle,
			_In_ ACCESS_MASK ProcessDesiredAccess,
			_In_ ACCESS_MASK ThreadDesiredAccess,
			_In_opt_ PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
			_In_opt_ PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
			_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
			_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
			_In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
			_Inout_ PPS_CREATE_INFO CreateInfo,
			_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
		);

	using pNtSuspendProcess = NTSTATUS
	(NTAPI*)
		(
			_In_ HANDLE ProcessHandle
		);

	using pNtResumeProcess = NTSTATUS
		(NTAPI*)
		(
			_In_ HANDLE ProcessHandle
		);

	using pNtQueueApcThread = NTSTATUS
		(NTAPI*)
		(
			_In_ HANDLE ThreadHandle,
			_In_ PPS_APC_ROUTINE ApcRoutine, // RtlDispatchAPC
			_In_opt_ PVOID ApcArgument1,
			_In_opt_ PVOID ApcArgument2,
			_In_opt_ PVOID ApcArgument3
		);

	using pNtMapViewOfSection = NTSTATUS
		(NTAPI*)
		(
			_In_ HANDLE SectionHandle,
			_In_ HANDLE ProcessHandle,
			_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
			_In_ ULONG_PTR ZeroBits,
			_In_ SIZE_T CommitSize,
			_Inout_opt_ PLARGE_INTEGER SectionOffset,
			_Inout_ PSIZE_T ViewSize,
			_In_ SECTION_INHERIT InheritDisposition,
			_In_ ULONG AllocationType,
			_In_ ULONG PageProtection
		);

	using pNtQueryInformationProcess = NTSTATUS
		(NTAPI*)
		(
			_In_ HANDLE ProcessHandle,
			_In_ PROCESSINFOCLASS ProcessInformationClass,
			_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
			_In_ ULONG ProcessInformationLength,
			_Out_opt_ PULONG ReturnLength
		);

	namespace TrueFuncPtrs {
		pLdrLoadDll trueLdrLoadDll{ nullptr };
		pNtOpenProcess trueNtOpenProcess{ nullptr };
		pNtAllocateVirtualMemoryEx trueNtAllocateVirtualMemoryEx{ nullptr };
		pNtWriteVirtualMemory trueNtWriteVirtualMemory{ nullptr };
		pNtCreateThreadEx trueNtCreateThreadEx{ nullptr };
		pNtCreateUserProcess trueNtCreateUserProcess{ nullptr };
		pNtSuspendProcess trueNtSuspendProcess{ nullptr };
		pNtResumeProcess trueNtResumeProcess{ nullptr };
		pNtQueueApcThread trueNtQueueApcThread{ nullptr };
		pNtMapViewOfSection trueNtMapViewOfSection{ nullptr };
		pNtQueryInformationProcess trueNtQueryInformationProcess{ nullptr };

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
				sensor->info("NtOpenProcess");
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
				sensor->info("NtAllocateVirtualMemoryEx");
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
				sensor->info("NtWriteVirtualMemory");
			}
			return TrueFuncPtrs::trueNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
		}


		NTSTATUS
			NTAPI
			detNtCreateThreadEx(
				_Out_ PHANDLE ThreadHandle,
				_In_ ACCESS_MASK DesiredAccess,
				_In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
				_In_ HANDLE ProcessHandle,
				_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
				_In_opt_ PVOID Argument,
				_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
				_In_ SIZE_T ZeroBits,
				_In_ SIZE_T StackSize,
				_In_ SIZE_T MaximumStackSize,
				_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
			) {
			if (sensor) {
				sensor->info("NtCreateThreadEx");
			}
			return TrueFuncPtrs::trueNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
		}

		NTSTATUS
			NTAPI
			detNtCreateUserProcess(
				_Out_ PHANDLE ProcessHandle,
				_Out_ PHANDLE ThreadHandle,
				_In_ ACCESS_MASK ProcessDesiredAccess,
				_In_ ACCESS_MASK ThreadDesiredAccess,
				_In_opt_ PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
				_In_opt_ PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
				_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
				_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
				_In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
				_Inout_ PPS_CREATE_INFO CreateInfo,
				_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
			) {
			if (sensor) {
				sensor->info("NtCreateUserProcess");
			}
			return TrueFuncPtrs::trueNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

		}

		NTSTATUS
			NTAPI
			detNtSuspendProcess(
				_In_ HANDLE ProcessHandle
			) {
			if (sensor) {
				sensor->info("NtSuspendProcess");
			}
			return TrueFuncPtrs::trueNtSuspendProcess(ProcessHandle);
		}

		NTSTATUS
			NTAPI
			detNtResumeProcess(
				_In_ HANDLE ProcessHandle
			) {
			if (sensor) {
				sensor->info("NtResumeProcess");
			}
			return TrueFuncPtrs::trueNtResumeProcess(ProcessHandle);
		}

		NTSTATUS
			NTAPI
			detNtQueueApcThread(
				_In_ HANDLE ThreadHandle,
				_In_ PPS_APC_ROUTINE ApcRoutine, // RtlDispatchAPC
				_In_opt_ PVOID ApcArgument1,
				_In_opt_ PVOID ApcArgument2,
				_In_opt_ PVOID ApcArgument3
			) {
			if (sensor) {
				sensor->info("NtQueueApcThread");
			}
			return TrueFuncPtrs::trueNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
		}

		NTSTATUS
			NTAPI
			detNtMapViewOfSection(
				_In_ HANDLE SectionHandle,
				_In_ HANDLE ProcessHandle,
				_Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
				_In_ ULONG_PTR ZeroBits,
				_In_ SIZE_T CommitSize,
				_Inout_opt_ PLARGE_INTEGER SectionOffset,
				_Inout_ PSIZE_T ViewSize,
				_In_ SECTION_INHERIT InheritDisposition,
				_In_ ULONG AllocationType,
				_In_ ULONG PageProtection
			) {
			if (sensor) {
				sensor->info("NtMapViewOfSection");
			}
			return TrueFuncPtrs::trueNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, PageProtection);
		}

		NTSTATUS
			NTAPI
			detNtQueryInformationProcess(
				_In_ HANDLE ProcessHandle,
				_In_ PROCESSINFOCLASS ProcessInformationClass,
				_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
				_In_ ULONG ProcessInformationLength,
				_Out_opt_ PULONG ReturnLength
			) {
			if (sensor) {
				sensor->info("NtQueryInformationProcess");
			}
			return TrueFuncPtrs::trueNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

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
		CREATE_HOOK(NtCreateThreadEx);
		CREATE_HOOK(NtCreateUserProcess);
		CREATE_HOOK(NtSuspendProcess);
		CREATE_HOOK(NtResumeProcess);
		CREATE_HOOK(NtQueueApcThread);
		CREATE_HOOK(NtMapViewOfSection);
		CREATE_HOOK(NtQueryInformationProcess);
		
		SPDLOG_INFO("[Hook] Hooks Created");
		return true;

	}

	bool attachHooks() {
		bool isError{ false };

		ATTACH_HOOK(LdrLoadDll);
		ATTACH_HOOK(NtOpenProcess);
		ATTACH_HOOK(NtAllocateVirtualMemoryEx);
		ATTACH_HOOK(NtWriteVirtualMemory);
		ATTACH_HOOK(NtCreateThreadEx);
		ATTACH_HOOK(NtCreateUserProcess);
		ATTACH_HOOK(NtSuspendProcess);
		ATTACH_HOOK(NtResumeProcess);
		ATTACH_HOOK(NtQueueApcThread);
		ATTACH_HOOK(NtMapViewOfSection);
		ATTACH_HOOK(NtQueryInformationProcess);


		return !isError;
	}
}

