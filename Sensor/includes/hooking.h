#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_DEBUG
#include "spdlog/spdlog.h"

namespace Monitor {
	bool createHooks();
	bool attachHooks();
}