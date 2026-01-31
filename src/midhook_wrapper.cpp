#include "midhook_wrapper.h"
#include "memory_utils.h"
#include "pointer_analysis.h"

#if SAFETYHOOK_ARCH_X86_64
#define IP_REG rip
#else
#define IP_REG eip
#endif

midhook_wrapper::midhook_wrapper(SafetyHookMid internal_hook) : hook(std::move(internal_hook))
{
    registry[get_trampoline().address()] = this;
    init_live_context();
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

    if (!internal_hook.has_value())
    {
        return nullptr;
    }

    return midhooks.emplace_back(std::make_shared<midhook_wrapper>(std::move(*internal_hook)));
}

void midhook_wrapper::init_live_context()
{
    static bool has_init = false;
    if (has_init == false)
    {
        live_context["EDI"] = register_definition{};
        live_context["ESI"] = register_definition{};
        live_context["EDX"] = register_definition{};
        live_context["ECX"] = register_definition{};
        live_context["EBX"] = register_definition{};
        live_context["EAX"] = register_definition{};
        live_context["EBP"] = register_definition{};
        live_context["ESP"] = register_definition{};
        live_context["EIP"] = register_definition{};
        has_init = true;
    }
}

void midhook_wrapper::handle_offsets(const char* name, const uintptr_t base_reg)
{
    for (auto& item : live_context[name].offset_definitions)
    {
        item.second.value = base_reg + item.first;
        if (item.second.do_override)
        {
            if (!memory_utils::safe_write(item.second.value, item.second.override_value))
            {
                item.second.do_override = false;
            }
        }
        if (show_live_window)
        {
            item.second.report = pointer_analysis::analyze_pointer(item.second.value);
        }
    }
}

void midhook_wrapper::destination(SafetyHookContext& ctx)
{
    last_hit_time = std::chrono::steady_clock::now();
    hit_amount++;

    live_context["EAX"].value = ctx.eax;
    live_context["ECX"].value = ctx.ecx;
    live_context["EDX"].value = ctx.edx;
    live_context["EBX"].value = ctx.ebx;
    live_context["ESI"].value = ctx.esi;
    live_context["EDI"].value = ctx.edi;
    live_context["EBP"].value = ctx.ebp;
    live_context["ESP"].value = ctx.esp;
    live_context["EIP"].value = ctx.eip;

    ctx.eax = live_context["EAX"].do_override ? live_context["EAX"].override_value : ctx.eax;
    ctx.ecx = live_context["ECX"].do_override ? live_context["ECX"].override_value : ctx.ecx;
    ctx.edx = live_context["EDX"].do_override ? live_context["EDX"].override_value : ctx.edx;
    ctx.ebx = live_context["EBX"].do_override ? live_context["EBX"].override_value : ctx.ebx;
    ctx.esi = live_context["ESI"].do_override ? live_context["ESI"].override_value : ctx.esi;
    ctx.edi = live_context["EDI"].do_override ? live_context["EDI"].override_value : ctx.edi;
    ctx.ebp = live_context["EBP"].do_override ? live_context["EBP"].override_value : ctx.ebp;
    ctx.trampoline_esp = live_context["ESP"].do_override ? live_context["ESP"].override_value : ctx.trampoline_esp;
    ctx.eip = live_context["EIP"].do_override ? live_context["EIP"].override_value : ctx.eip;

    if (show_live_window)
    {
        live_context["EAX"].report = pointer_analysis::analyze_pointer(ctx.eax);
        live_context["ECX"].report = pointer_analysis::analyze_pointer(ctx.ecx);
        live_context["EDX"].report = pointer_analysis::analyze_pointer(ctx.edx);
        live_context["EBX"].report = pointer_analysis::analyze_pointer(ctx.ebx);
        live_context["ESI"].report = pointer_analysis::analyze_pointer(ctx.esi);
        live_context["EDI"].report = pointer_analysis::analyze_pointer(ctx.edi);
        live_context["EBP"].report = pointer_analysis::analyze_pointer(ctx.ebp);
        live_context["ESP"].report = pointer_analysis::analyze_pointer(ctx.esp);
        // EIP is trampoline address no need to analyze
    }

    handle_offsets("EAX", ctx.eax);
    handle_offsets("ECX", ctx.ecx);
    handle_offsets("EDX", ctx.edx);
    handle_offsets("EBX", ctx.ebx);
    handle_offsets("ESI", ctx.esi);
    handle_offsets("EDI", ctx.edi);
    handle_offsets("EBP", ctx.ebp);
    handle_offsets("ESP", ctx.esp);
    handle_offsets("EIP", ctx.esp);
}

void midhook_wrapper::trampoline(SafetyHookContext& ctx)
{
    if (auto it = registry.find(ctx.IP_REG); it != registry.end() && it->second)
    {
        it->second->destination(ctx);
    }
}
