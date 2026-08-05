#include <fstream>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include "includes/config.h"
using json = nlohmann::json;

namespace {

    template <typename T>
    std::optional<T> requireField(const json& obj, std::string_view key, std::string_view context) {
        auto it = obj.find(key);
        if (it == obj.end() || it->is_null()) {
            spdlog::error("[Config] missing key '{}' in {}", key, context);
            return std::nullopt;
        }

        bool typeOk = true;
        if constexpr (std::is_same_v<T, std::string>) {
            typeOk = it->is_string();
        }
        else if constexpr (std::is_same_v<T, int> || std::is_same_v<T, long>) {
            typeOk = it->is_number_integer();
        }
        else if constexpr (std::is_same_v<T, bool>) {
            typeOk = it->is_boolean();
        }

        if (!typeOk) {
            spdlog::error("[Config] invalid type for key '{}' in {}", key, context);
            return std::nullopt;
        }
        return it->get<T>();
    }

    const json* requireNode(const json& obj, std::string_view key, std::string_view context, bool (json::* typeCheck)() const) {
        auto it = obj.find(key);
        if (it == obj.end() || it->is_null()) {
            spdlog::error("[Config] missing key '{}' in {}", key, context);
            return nullptr;
        }
        if (!((*it).*typeCheck)()) {
            spdlog::error("[Config] invalid type for key '{}' in {}", key, context);
            return nullptr;
        }
        return &(*it);
    }

}
namespace Config {
    std::optional<Config> getConfig(std::string_view configPath) {
        std::ifstream ifFile(configPath.data());
        if (!ifFile.is_open()) {
            spdlog::error("[Config] Error opening config file");
            return std::nullopt;
        }

        json configJson;
        try {
            configJson = json::parse(ifFile);
        }
        catch (const json::parse_error& e) {
            spdlog::error("[Config] Failed to parse config JSON: {}", e.what());
            return std::nullopt;
        }

        Config config;

        auto logLevel = requireField<std::string>(configJson, "log_level", "root");
        if (!logLevel) return std::nullopt;
        config.logLevel = *logLevel;
        spdlog::set_level(spdlog::level::from_str(config.logLevel));

        const json* payload = requireNode(configJson, "payload_dll", "root", &json::is_object);
        if (!payload) return std::nullopt;

        auto path64 = requireField<std::string>(*payload, "path_64", "payload_dll");
        auto path32 = requireField<std::string>(*payload, "path_32", "payload_dll");
        auto calleeName = requireField<std::string>(*payload, "callee_name", "payload_dll");

        if (!path64 || !path32 || !calleeName) return std::nullopt;

        config.path64 = *path64;
        config.path32 = *path32;
        config.calleeName = *calleeName;

        const json* injector = requireNode(configJson, "injector", "root", &json::is_object);
        if (!injector) return std::nullopt;

        auto mode = requireField<std::string>(*injector, "mode", "injector");
        if (!mode) return std::nullopt;

        if (*mode == "once") {
            config.injectorMode = InjectorMode::INJECT_ONCE;
        }
        else if (*mode == "continuous") {
            config.injectorMode = InjectorMode::INJECT_CONT;
        }
        else if (*mode == "create") {
            config.injectorMode = InjectorMode::INJECT_CREATE;
        }
        else {
            spdlog::error("[Config] invalid value for 'mode': {}", *mode);
            return std::nullopt;
        }

        if (config.injectorMode == InjectorMode::INJECT_ONCE) {
            const json* targetPids = requireNode(*injector, "target_pids", "injector", &json::is_array);
            if (!targetPids) return std::nullopt;

            for (const auto& pid : *targetPids) {
                if (!pid.is_number_integer()) {
                    spdlog::error("[Config] target_pids must contain only integers");
                    return std::nullopt;
                }
                config.processID.push_back(pid.get<long>());
            }
            return config;
        }

        const json* targetNames = requireNode(*injector, "target_names", "injector", &json::is_array);
        if (!targetNames) return std::nullopt;

        for (const auto& name : *targetNames) {
            if (!name.is_string()) {
                spdlog::error("[Config] target_names must contain only strings");
                return std::nullopt;
            }
            config.processName.push_back(name.get<std::string>());
        }

        if (config.injectorMode == InjectorMode::INJECT_CREATE) {
            return config;
        }

        auto interval = requireField<int>(*injector, "search_intervel_seconds", "injector");
        if (!interval) return std::nullopt;
        config.searchIntervalSeconds = *interval;

        return config;
    }
}
