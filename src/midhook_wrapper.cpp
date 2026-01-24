#include "midhook_wrapper.h"
#include "safetyhook/ContextEx.h"
#include "memory_utils.h"

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#else
#define IP_REG eip
#endif

// Jargon to get the m_hook private member
template<typename T, auto P> struct Stealer { friend auto get(T) { return P; } };
struct MidHookTag { using type = safetyhook::InlineHook safetyhook::MidHook::*; };
template struct Stealer<MidHookTag, &safetyhook::MidHook::m_hook>;
auto get(MidHookTag);

midhook_wrapper::~midhook_wrapper()
{
    hook.disable();
    registry.erase(get_trampoline().address());
    hook = {};
}

inline const safetyhook::Allocation& midhook_wrapper::get_trampoline() const
{
    return (this->hook.*get(MidHookTag{})).trampoline();
}

std::shared_ptr<midhook_wrapper> midhook_wrapper::create(void* target)
{
    if (!memory_utils::is_executable_pointer(target))
    {
        return nullptr;
    }

    if (std::any_of(midhooks.begin(), midhooks.end(), [target](const auto& hook_ptr)
        {
            return hook_ptr->hook.target_address() == reinterpret_cast<uintptr_t>(target);
        }))
    {
        return nullptr;
    }

    auto internal_hook = safetyhook::MidHook::create(target, trampoline, safetyhook::MidHook::Flags::StartDisabled);

    if (!internal_hook)
    {
        return nullptr;
    }

    std::shared_ptr<midhook_wrapper> object = std::make_shared<midhook_wrapper>(std::move(*internal_hook));
    midhooks.push_back(object);

    return object;
}

midhook_wrapper::midhook_wrapper(SafetyHookMid internal_hook) : hook(std::move(internal_hook))
{
    registry[get_trampoline().address()] = this;
}


void midhook_wrapper::destination(SafetyHookContext& ctx)
{
    if (log.tellp() > MAX_LOG_SIZE)
    {
        this->clear_log();
        log << "[Log cleared to prevent overflow]\n\n";
    }

    last_hit_time = std::chrono::steady_clock::now();
    hit_amount++;

    log << "-------------------------------" << "\n";
    log << "CPU Context at: 0x" << std::hex << std::uppercase << hook.target_address() << "\n";
    log << "-------------------------------" << "\n";
    log << reinterpret_cast<const safetyhook::ContextEx&>(ctx).to_string();
}

void midhook_wrapper::trampoline(SafetyHookContext& ctx)
{
    if (auto it = registry.find(ctx.IP_REG); it != registry.end() && it->second)
    {
        it->second->destination(ctx);
    }
}
