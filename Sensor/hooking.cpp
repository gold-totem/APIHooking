#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
#include <spdlog/spdlog.h>

// This line is completely removed by the preprocessor if SPDLOG_ACTIVE_LEVEL > SPDLOG_LEVEL_DEBUG
SPDLOG_DEBUG("Value: {}",12);