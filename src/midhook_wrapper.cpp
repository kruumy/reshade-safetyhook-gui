#include "midhook_wrapper.h"
#include "memory_utils.h"

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#else
#define IP_REG eip
#endif


midhook_wrapper::midhook_wrapper(SafetyHookMid internal_hook) : hook(std::move(internal_hook))
{
    registry[get_trampoline().address()] = this;
}

midhook_wrapper::~midhook_wrapper()
{
    hook.disable();
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

void midhook_wrapper::destination(SafetyHookContext& ctx)
{
    last_hit_time = std::chrono::steady_clock::now();

    ctx.eax = context_override.override_eax ? context_override.eax : ctx.eax;
    ctx.ebp = context_override.override_ebp ? context_override.ebp : ctx.ebp;
    ctx.ebx = context_override.override_ebx ? context_override.ebx : ctx.ebx;
    ctx.ecx = context_override.override_ecx ? context_override.ecx : ctx.ecx;
    ctx.edi = context_override.override_edi ? context_override.edi : ctx.edi;
    ctx.edx = context_override.override_edx ? context_override.edx : ctx.edx;
    ctx.eflags = context_override.override_eflags ? context_override.eflags : ctx.eflags;
    ctx.eip = context_override.override_eip ? context_override.eip : ctx.eip;
    ctx.esi = context_override.override_esi ? context_override.esi : ctx.esi;
    ctx.trampoline_esp = context_override.override_esp ? context_override.esp : ctx.trampoline_esp;

    last_context = context_wrapper(ctx, show_live_window);
    hit_amount++;
}

void midhook_wrapper::trampoline(SafetyHookContext& ctx)
{
    if (auto it = registry.find(ctx.IP_REG); it != registry.end() && it->second)
    {
        it->second->destination(ctx);
    }
}
