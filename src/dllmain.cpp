#include <imgui.h>
#include <reshade.hpp>
#include <safetyhook.hpp>

static void draw_window(reshade::api::effect_runtime* runtime)
{
    ImGui::TextUnformatted("Some text");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!reshade::register_addon(hinstDLL))
        {
            return FALSE;
        }
        reshade::register_overlay("safetyhook-gui", &draw_window);
        break;
    case DLL_PROCESS_DETACH:
        reshade::unregister_addon(hinstDLL);
        break;
    }
    return TRUE;
}