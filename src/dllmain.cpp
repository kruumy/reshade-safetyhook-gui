#include "gui/gui.hpp"
#include <Zydis/Zydis.h>
#include <imgui.h>
#include <reshade.hpp>
#include <safetyhook.hpp>
#include <windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!reshade::register_addon(hinstDLL))
        {
            return FALSE;
        }
        reshade::register_overlay(nullptr, &gui::draw);
        break;
    case DLL_PROCESS_DETACH:
        reshade::unregister_addon(hinstDLL);
        break;
    default:
        break;
    }

    return TRUE;
}