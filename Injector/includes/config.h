#pragma once
#include <vector>
#include <string>
#include <optional>

namespace Config {

    enum class InjectorMode {
        INJECT_ONCE,
        INJECT_CREATE
    };

    struct Config {
        InjectorMode injectorMode{};
        std::vector<std::string> processName;
        std::vector<long> processIDs;
        std::string path64;
        std::string path32;
        std::string calleeName;
        std::string pathStartupDll;
        std::string logLevel;
        static std::optional<Config> getConfig(std::string_view configPath);
    };
    
}