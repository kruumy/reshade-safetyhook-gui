#include <imgui.h>
#include <reshade.hpp>
#include <windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(nullptr, "Hello World!", "Hello World!", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        break;
    default:
        break;
    }

    return TRUE;
}