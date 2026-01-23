#pragma once
#include <vector>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <windows.h>
#include <safetyhook.hpp>
#include "midhook_extensions.h"

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#else
#define IP_REG eip
#endif

class midhook_definition
{
public:

    bool show_log_window = false;
    std::chrono::steady_clock::time_point last_hit_time{};
    SafetyHookMid hook;

    explicit midhook_definition(void* target)
    {
        auto result = safetyhook::MidHook::create(
            target,
            &midhook_definition::trampoline,
            safetyhook::MidHook::Flags::StartDisabled);

        if (!result)
        {
            reshade::log::message(reshade::log::level::error, "Failed to create midhook");
            return;
        }

        hook = std::move(*result);

        registry[midhook_extensions::get_trampoline(hook).address()] = this;
    }

    ~midhook_definition()
    {
        uintptr_t tramp_ip = midhook_extensions::get_trampoline(hook).address();

        registry.erase(tramp_ip);

        hook = {};
    }

    inline std::string_view get_log() const
    {
        return log.view();
    }

    inline void clear_log()
    {
        log.str("");
        log.clear();
    }

private:
    inline static std::unordered_map<uintptr_t, midhook_definition*> registry;
    std::stringstream log;
    const size_t MAX_LOG_SIZE = 100 * 1024;

    static void print_context(std::ostream& os, const SafetyHookContext& ctx, uintptr_t target_addr)
    {
        os << "-------------------------------" << "\n";
        os << "CPU Context at: 0x" << std::hex << std::uppercase << target_addr << "\n";
        os << "-------------------------------" << "\n";

        auto log_reg = [&](const char* name, uintptr_t value)
        {
            os << name << ": 0x" << std::hex << std::uppercase << value << "\n";
        };

#if SAFETYHOOK_ARCH_X86_64
        log_reg("RAX", ctx.rax); log_reg("RBX", ctx.rbx);
        log_reg("RCX", ctx.rcx); log_reg("RDX", ctx.rdx);
        log_reg("RSI", ctx.rsi); log_reg("RDI", ctx.rdi);
        log_reg("RBP", ctx.rbp); log_reg("RSP", ctx.rsp);
        log_reg("RIP", ctx.rip);
#else
        log_reg("EAX", ctx.eax); log_reg("EBX", ctx.ebx);
        log_reg("ECX", ctx.ecx); log_reg("EDX", ctx.edx);
        log_reg("EBP", ctx.ebp); log_reg("ESP", ctx.esp);
        log_reg("EIP", ctx.eip);
#endif
        os << std::endl;
    }

    void destination(SafetyHookContext& ctx)
    {
        last_hit_time = std::chrono::steady_clock::now();

        print_context(log,ctx, hook.target_address());

        if (log.tellp() > MAX_LOG_SIZE)
        {
            this->clear_log();
            log << "[Log cleared to prevent overflow]\n";
        }
    }

    static void trampoline(SafetyHookContext& ctx)
    {
        if (auto it = registry.find(ctx.IP_REG); it != registry.end())
        {
            it->second->destination(ctx);
        }
    }
};
