#include <map>
#include <windows.h>
#include <safetyhook.hpp>
#include <string>
#include <format>

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#elif SAFETYHOOK_ARCH_X86_32
#define IP_REG eip
#endif

class midhook_definition
{
public:
    void* target = nullptr;
    bool is_enabled = false;

    void destination(SafetyHookContext& ctx)
    {
        std::string log_msg = std::format("Midhook triggered for object at target: 0x{:X}", reinterpret_cast<uintptr_t>(target));
        std::string ip_msg = std::format("Actual IP at trigger: 0x{:X}", static_cast<uintptr_t>(ctx.IP_REG));

        reshade::log::message(reshade::log::level::info, log_msg.c_str());
        reshade::log::message(reshade::log::level::info, ip_msg.c_str());
    }

    void enable()
    {
        if (target == nullptr) return;

        registry[target] = this;

        hook = safetyhook::create_mid(target, trampoline);
        is_enabled = true;
    }

    void disable()
    {
        if (is_enabled)
        {
            hook = {};
            registry.erase(target);
            is_enabled = false;
        }
    }

private:
    SafetyHookMid hook;

    inline static std::map<void*, midhook_definition*> registry;

    static void trampoline(SafetyHookContext& ctx)
    {
        void* current_ip = reinterpret_cast<void*>(ctx.IP_REG);
        auto it = registry.find(current_ip);

        if (it == registry.end() && !registry.empty())
        {
            auto lb = registry.lower_bound(current_ip);
            if (lb != registry.begin())
            {
                it = std::prev(lb);
            }
        }

        if (it != registry.end())
        {
            it->second->destination(ctx);
        }
    }
};