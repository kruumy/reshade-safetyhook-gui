#pragma once
#include <safetyhook.hpp>
#include <reshade.hpp>

class midhook_definition
{
public:
	void* target = 0x0;
    bool is_enabled;

    void static print_context(SafetyHookContext& ctx)
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

	void static destination(SafetyHookContext& ctx)
	{
        print_context(ctx);
	}

	void enable()
	{
		hook = safetyhook::create_mid(target, &destination);
        is_enabled = true;
	}
	void disable()
	{
		hook = {};
        is_enabled = false;
	}

private:
    SafetyHookMid hook;
};