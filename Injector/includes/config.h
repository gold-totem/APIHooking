#include <vector>
#include <string>
#include <optional>

namespace config {

    enum class InjectorMode {
        INJECT_ONCE,
        INJECT_CONT,
        INJECT_CREATE
    };

    struct Config {
        InjectorMode injectorMode{};
        std::vector<std::string> processName;
        std::vector<long> processID;
        std::string path64;
        std::string path32;
        std::string calleeName;
        std::string logLevel;
        int searchIntervalSeconds{ 10 };
    };
    static std::optional<Config> getConfig(std::string_view configPath);
}