#pragma once
#include "config.h"
#include <Windows.h>
namespace Injector {
    class Injector {

    public:
        static std::optional<Injector> get(const Config::Config& c);

        bool run();

    private:
        Injector();

        const struct ProcConsts {
            const std::string_view dllPath;
            const uintptr_t calleeDelta;
            const uintptr_t loadLibraryDelta;

            ProcConsts(std::string_view dllPath,
                uintptr_t hookDelta,
                uintptr_t loadDelta
            ) :
                dllPath{ dllPath },
                calleeDelta{ hookDelta },
                loadLibraryDelta{ loadDelta }
            {

            }
        } proc64, proc32;

        const Config::Config& config;

        Injector(ProcConsts p64, ProcConsts p32, const Config::Config& c) :proc64(p64), proc32(p32), config(c) {}

        bool injectPID(DWORD pid);
        void modeOnce();
        void modeCreate();


    };
}
