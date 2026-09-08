#pragma once
#include <vector>
#include <string>
#include <optional>

namespace Config {

    struct Config {
        std::vector<std::string> processNames;
        std::vector<long> processIDs;
        std::string path64;
        std::string path32;
        std::string calleeName;
        std::string logLevel;
        static std::optional<Config> getConfig(std::string_view configPath);
    };
    
}