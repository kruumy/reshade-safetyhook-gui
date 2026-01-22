#include <map>
#include <windows.h>
#include <safetyhook.hpp>
#include <string>
#include <format>
#include <unordered_map>
#include "private_member_stealer.h"
#include <chrono>

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#elif SAFETYHOOK_ARCH_X86_32
#define IP_REG eip
#endif

struct MidHookInlineTag
{
    typedef safetyhook::InlineHook safetyhook::MidHook::* type;
};

template struct private_member_stealer<MidHookInlineTag, &safetyhook::MidHook::m_hook>;
safetyhook::InlineHook safetyhook::MidHook::* get_member(MidHookInlineTag);


class midhook_definition
{
public:
    void* target = nullptr;
    bool is_enabled = false;
    std::chrono::steady_clock::time_point last_hit_time{};

    void destination(SafetyHookContext& ctx)
    {
        last_hit_time = std::chrono::steady_clock::now();
    }

    void enable()
    {
        if (target == nullptr) return;

        auto result = safetyhook::MidHook::create(target, &trampoline);
        if (result)
        {
            hook = std::move(*result);
            auto& m_hook = hook.*get_member(MidHookInlineTag{});

            instance_registry[m_hook.trampoline().address()] = this;

            is_enabled = true;
        }
    }

    void disable()
    {
        if (is_enabled)
        {
            auto& m_hook = hook.*get_member(MidHookInlineTag{});
            uintptr_t tramp_addr = m_hook.trampoline().address();

            instance_registry.erase(tramp_addr);
            hook = {};
            is_enabled = false;
        }
    }

    

private:
    SafetyHookMid hook;

    inline static std::unordered_map<uintptr_t, midhook_definition*> instance_registry;

    static void trampoline(SafetyHookContext& ctx)
    {
        if (instance_registry.contains(ctx.IP_REG))
        {
            midhook_definition* instance = instance_registry[ctx.IP_REG];
            instance->destination(ctx);
            return;
        }

        std::string ip_msg = std::format("Could not find IP in registry: 0x{:X}", static_cast<uintptr_t>(ctx.IP_REG));
        reshade::log::message(reshade::log::level::error, ip_msg.c_str());
    }
};