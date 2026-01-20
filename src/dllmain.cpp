#include <imgui.h>
#include <reshade.hpp>
#include <safetyhook.hpp>
#include <string>
#include <windows.h>

static safetyhook::InlineHook g_hook;
static char g_address_buffer[128] = "0x4F8D90"; // TODO: temp default addr for testing, remove later

void hooked_function_callback()
{
    reshade::log::message(reshade::log::level::info, "Target address was called.");
}

static void draw_window(reshade::api::effect_runtime* runtime)
{
    ImGui::InputText("Target Address", g_address_buffer, sizeof(g_address_buffer));

    if (ImGui::Button("Apply Hook"))
    {
        uintptr_t target_addr = std::stoull(g_address_buffer, nullptr, 16);
        g_hook = safetyhook::create_inline(reinterpret_cast<void*>(target_addr), reinterpret_cast<void*>(hooked_function_callback));
        reshade::log::message(reshade::log::level::info,"Successfully applied safetyhook");
    }

    if (ImGui::Button("Remove Hook"))
    {
        g_hook = {};
        reshade::log::message(reshade::log::level::info, "Hook removed.");
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        if (!reshade::register_addon(hinstDLL))
        {
            return FALSE;
        }
        reshade::register_overlay("SafetyHook GUI", &draw_window);
        break;
    case DLL_PROCESS_DETACH:
        g_hook = {};
        reshade::unregister_addon(hinstDLL);
        break;
    }
    return TRUE;
}