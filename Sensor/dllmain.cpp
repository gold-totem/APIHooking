#include "pch.h"
#include <detours/detours.h>
#include "includes/hooking.h"
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        Monitor::createHooks();
        DetourUpdateThread(GetCurrentThread());
        Monitor::createHooks();
        DetourTransactionCommit();
        break;

    case DLL_THREAD_ATTACH: 
        break;
    case DLL_THREAD_DETACH: 
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}