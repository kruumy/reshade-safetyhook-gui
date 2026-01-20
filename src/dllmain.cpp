#include <imgui.h>
#include <reshade.hpp>
#include <safetyhook.hpp>
#include <string>
#include <windows.h>

static SafetyHookMid g_hook;
static char g_address_buffer[128] = "0x4F8D90"; // TODO: temp default addr for testing, remove later
void print_context(SafetyHookContext& ctx)
{
    char buffer[256];
    reshade::log::message(reshade::log::level::info, "--- MidHook Context ---");

#if SAFETYHOOK_ARCH_X86_64
    // Logging 64-bit General Purpose Register
    sprintf_s(buffer, sizeof(buffer), "RAX: 0x%016llX | RBX: 0x%016llX", ctx.rax, ctx.rbx);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "RCX: 0x%016llX | RDX: 0x%016llX", ctx.rcx, ctx.rdx);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "RSI: 0x%016llX | RDI: 0x%016llX", ctx.rsi, ctx.rdi);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "R8:  0x%016llX | R9:  0x%016llX", ctx.r8, ctx.r9);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "RSP: 0x%016llX | RBP: 0x%016llX", ctx.rsp, ctx.rbp);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "RIP: 0x%016llX | RFL: 0x%016llX", ctx.rip, ctx.rflags);
    reshade::log::message(reshade::log::level::info, buffer);

    // Iterating over XMM registers to mirror the floating point state
    for (int i = 0; i < 16; ++i)
    {
        float* f = reinterpret_cast<float*>(&(&ctx.xmm0)[i]);
        sprintf_s(buffer, sizeof(buffer), "XMM%d: [%.2f, %.2f, %.2f, %.2f]", i, f[0], f[1], f[2], f[3]);
        reshade::log::message(reshade::log::level::info, buffer);
    }
#else
    // Logging 32-bit General Purpose Registers
    sprintf_s(buffer, sizeof(buffer), "EAX: 0x%08X | EBX: 0x%08X", ctx.eax, ctx.ebx);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "ECX: 0x%08X | EDX: 0x%08X", ctx.ecx, ctx.edx);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "ESP: 0x%08X | EBP: 0x%08X", ctx.esp, ctx.ebp);
    reshade::log::message(reshade::log::level::info, buffer);

    sprintf_s(buffer, sizeof(buffer), "EIP: 0x%08X | EFL: 0x%08X", ctx.eip, ctx.eflags);
    reshade::log::message(reshade::log::level::info, buffer);
#endif

    reshade::log::message(reshade::log::level::info, "-----------------------");
}

void hooked_function_callback(SafetyHookContext& ctx)
{
    print_context(ctx);
}

static void draw_window(reshade::api::effect_runtime* runtime)
{
    ImGui::InputText("Target Address", g_address_buffer, sizeof(g_address_buffer));

    if (ImGui::Button("Apply Hook"))
    {
        uintptr_t target_addr = std::stoull(g_address_buffer, nullptr, 16);
        g_hook = safetyhook::create_mid(reinterpret_cast<void*>(target_addr), &hooked_function_callback);
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