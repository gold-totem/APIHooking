#include <userenv.h>

#include "pch.h"
#include "detours/detours.h"
#include "includes/hooking.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#pragma comment(linker, "/EXPORT:DetourFinishHelperProcess,@1,NONAME")
namespace Monitor{

	bool initLogger() {

		char processName[MAX_PATH];
		if (GetModuleFileNameA(nullptr, processName, MAX_PATH) == 0) {
			return false;
		}

		char path[MAX_PATH];

		memset(path, 0, sizeof(path));

		if (!ExpandEnvironmentStringsForUserA(
			NULL,
			"%PROGRAMDATA%",
			path,
			sizeof(path)
		)) {
			return false;
		}

		auto now = std::chrono::system_clock::now();
		auto now_seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);

		std::string time = std::format("{:%Y-%m-%d_%H-%M-%S}", now_seconds);

		std::string log_path = path;

		log_path += '\\' + std::filesystem::path(processName).stem().string() + '_' + std::to_string(GetCurrentProcessId()) + '_' + time + ".log";

		auto sensor = spdlog::basic_logger_mt("Sensor", log_path, true);
		spdlog::set_level(spdlog::level::info);

		return true;
	}
}
extern "C" __declspec(dllexport) bool hookProc() {


	SPDLOG_INFO("Running hookProc.");

	if (!Monitor::initLogger()) {
		SPDLOG_ERROR("Failed initializing logger.");
	}

	if (!Monitor::createHooks()) {
		SPDLOG_ERROR("createHooks failed.");
		return false;
	}

	SPDLOG_INFO("Successfully initialized hooks.");

	if (DetourTransactionBegin() != NO_ERROR) {
		SPDLOG_ERROR("DetourTransactionBegin failed.");
		return false;
	}

	SPDLOG_INFO("DetourTransactionBegin successful.");

	HANDLE hThread = GetCurrentThread();
	if (!hThread) {
		DetourTransactionAbort();
		SPDLOG_ERROR("GetCurrentThread failed: {}.", GetLastError());
		return false;
	}

	SPDLOG_INFO("GetCurrentThread successful.");

	if ((DetourUpdateThread(hThread)) != NO_ERROR) {
		SPDLOG_ERROR("DetourUpdateThread failed.");
		DetourTransactionAbort();
		return false;
	}
	SPDLOG_INFO("DetourUpdateThread successful for current thread.");

	HPSSWALK walkMarkerHandle{ 0 };

	DWORD pssStatus = PssWalkMarkerCreate(NULL, &walkMarkerHandle);
	if (pssStatus != ERROR_SUCCESS) {
		SPDLOG_ERROR("PssWalkMarkerCreate failed");
		return false;
	}


	std::vector<HANDLE> threadHandles;
	
	HPSS snapshotHandle{ 0 };

	//-------------------

	pssStatus = PssCaptureSnapshot(GetCurrentProcess(), PSS_CAPTURE_THREADS, NULL, &snapshotHandle);
	if (pssStatus != ERROR_SUCCESS) {
		SPDLOG_ERROR("PssCaptureSnapshot failed");
		return false;
	}

	PSS_THREAD_ENTRY threadEntry{ 0 };
	while (ERROR_SUCCESS == PssWalkSnapshot(snapshotHandle, PSS_WALK_THREADS, walkMarkerHandle, &threadEntry, sizeof(threadEntry))) {
		if (GetCurrentThreadId() == threadEntry.ThreadId)
			continue;

		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.ThreadId);
		if (!hThread) {
			SPDLOG_ERROR("OpenThread failed");
			DetourTransactionAbort();
			PssWalkMarkerFree(walkMarkerHandle);
			PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);
			for (auto& handle : threadHandles) {
				CloseHandle(handle);
			}
			return false;
		}
		SPDLOG_INFO("OpenThread successful.");
		threadHandles.push_back(hThread);

		if ((DetourUpdateThread(hThread)) != NO_ERROR) {
			SPDLOG_ERROR("DetourUpdateThread failed.");
			DetourTransactionAbort();
			PssWalkMarkerFree(walkMarkerHandle);
			PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);
			for (auto& handle : threadHandles) {
				CloseHandle(handle);
			}
			return false;
		}
	}
	 //--------------------
	SPDLOG_INFO("DetourUpdateThread successful for other threads.");

	PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);

	if (!Monitor::attachHooks()) {
		SPDLOG_ERROR("AttachHooks failed.");
		DetourTransactionAbort();
		return false;
	}
	SPDLOG_INFO("attachHooks successful");
	
	if ((DetourTransactionCommit()) != NO_ERROR) {
		SPDLOG_ERROR("DetourTransactionCommit failed.");
		DetourTransactionAbort();
		return false;
	}
	SPDLOG_INFO("successfully attached detours.");

	pssStatus = PssWalkMarkerFree(walkMarkerHandle);

	for (auto& handle : threadHandles) {
		CloseHandle(handle);
	}

	return true;
}