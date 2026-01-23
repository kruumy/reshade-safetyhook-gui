#include "midhook_wrapper.h"
#include "safetyhook/ContextEx.h"

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#else
#define IP_REG eip
#endif

midhook_wrapper::midhook_wrapper(void* target)
{
    if (auto result = safetyhook::MidHook::create(target, trampoline, safetyhook::MidHook::Flags::StartDisabled))
    {
        hook = std::move(*result);
        registry[get_trampoline().address()] = this;
    }
}

midhook_wrapper::~midhook_wrapper()
{
    registry.erase(get_trampoline().address());
    hook = {};
}


// Jargon to get the m_hook private member
template<typename T, auto P> struct Stealer { friend auto get(T) { return P; } };
struct MidHookTag { using type = safetyhook::InlineHook safetyhook::MidHook::*; };
template struct Stealer<MidHookTag, &safetyhook::MidHook::m_hook>;
auto get(MidHookTag);

inline const safetyhook::Allocation& midhook_wrapper::get_trampoline() const
{
    return (this->hook.*get(MidHookTag{})).trampoline();
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
    if (auto it = registry.find(ctx.IP_REG); it != registry.end())
    {
        it->second->destination(ctx);
    }
}
