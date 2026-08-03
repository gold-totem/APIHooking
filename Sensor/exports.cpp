#include "pch.h"
#include "detours/detours.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
namespace {
	namespace Logger {
		void initLogger() {
			char path[MAX_PATH];
			if (GetModuleFileNameA(nullptr, path, MAX_PATH) == 0) {
				return;
			}
			std::string log_path = "d:/logs/" + std::filesystem::path(path).stem().string() + ".log";

			std::filesystem::create_directories("d:/logs");

			auto logger = spdlog::basic_logger_mt("Monitor", log_path, true);

			spdlog::set_default_logger(logger);
			spdlog::set_level(spdlog::level::debug);
		}
	}
}

extern "C" __declspec(dllexport) bool initHooks() {
	Logger::initLogger();
	spdlog::info("Running initHooks.");

	if (!Monitor::createHooks()) {
		spdlog::error("createHooks failed.");
		return false;
	}
	spdlog::info("createHooks successful.");

	if (DetourTransactionBegin() != NO_ERROR) {
		spdlog::error("DetourTransactionBegin failed.");
		return false;
	}
	spdlog::info("DetourTransactionBegin successful.");
	HANDLE hThread = GetCurrentThread();
	if (!hThread) {
		DetourTransactionAbort();
		spdlog::error("GetCurrentThread failed: {}.", GetLastError());
		return false;
	}

	spdlog::info("GetCurrentThread successful.");

	if ((DetourUpdateThread(hThread)) != NO_ERROR) {
		spdlog::error("DetourUpdateThread failed.");
		DetourTransactionAbort();
		return false;
	}
	spdlog::info("DetourUpdateThread successful for current thread.");

	HPSS snapshotHandle{ 0 };
	DWORD pssStatus = PssCaptureSnapshot(GetCurrentProcess(), PSS_CAPTURE_THREADS, NULL, &snapshotHandle);
	if (pssStatus != ERROR_SUCCESS) {
		spdlog::error("PssCaptureSnapshot failed");
		return 1;
	}

	HPSSWALK walkMarkerHandle{ 0 };
	pssStatus = PssWalkMarkerCreate(NULL, &walkMarkerHandle);
	if (pssStatus != ERROR_SUCCESS) {
		spdlog::error("PssWalkMarkerCreate failed");
		return 1;
	}

	std::vector<HANDLE> threadHandles;

	PSS_THREAD_ENTRY threadEntry{ 0 };
	while (ERROR_SUCCESS == PssWalkSnapshot(snapshotHandle, PSS_WALK_THREADS, walkMarkerHandle, &threadEntry, sizeof(threadEntry))) {
		if (GetCurrentThreadId() == threadEntry.ThreadId)
			continue;

		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.ThreadId);
		if (!hThread) {
			spdlog::error("OpenThread failed");
			return 1;
		}
		threadHandles.push_back(hThread);
		spdlog::info("OpenThread successful.");

		if ((DetourUpdateThread(hThread)) != NO_ERROR) {
			spdlog::error("DetourUpdateThread failed.");
			DetourTransactionAbort();
			CloseHandle(hThread);
			return false;
		}

		spdlog::info("DetourUpdateThread successful.");
	}

	spdlog::info("DetourUpdateThread successful for other threads.");
	bool returnValue = true;

	if (!Monitor::attachHooks()) {
		spdlog::error("AttachHooks failed: {}.");
		DetourTransactionAbort();
		return false;
	}
	spdlog::info("attachHooks successful");
	if ((DetourTransactionCommit()) != NO_ERROR) {
		spdlog::error("DetourTransactionCommit failed: {}.");
		DetourTransactionAbort();
		return false;
	}
	spdlog::info("successfully attached detours.");

	pssStatus = PssWalkMarkerFree(walkMarkerHandle);
	if (pssStatus != ERROR_SUCCESS) {
		spdlog::error("PssWalkMarkerFree failed: {}.", GetLastError());
	}
	for (auto& handle : threadHandles) {
		CloseHandle(handle);
	}

	return true;
}