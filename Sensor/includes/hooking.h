#pragma once

#ifdef _DEBUG
	#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#else
	#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_OFF
#endif // _DEBUG


#include "spdlog/spdlog.h"

namespace Monitor {
	bool createHooks();
	bool attachHooks();
	bool initLogger();
}