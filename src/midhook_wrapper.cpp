#include "midhook_wrapper.hpp"
#include "memory_utils.hpp"
#include "pointer_analysis.hpp"
#include <imgui.h>
#include <reshade.hpp>

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
template <typename T, auto P> struct Stealer
{
    friend auto get(T)
    {
        return P;
    }
};
struct MidHookTag
{
    using type = safetyhook::InlineHook safetyhook::MidHook::*;
};
template struct Stealer<MidHookTag, &safetyhook::MidHook::m_hook>;
auto get(MidHookTag);
inline const safetyhook::Allocation& midhook_wrapper::get_trampoline() const
{
    return (this->hook.*get(MidHookTag{})).trampoline();
}

void midhook_wrapper::on_imgui_render()
{
    current_frame.store(ImGui::GetFrameCount(), std::memory_order_relaxed);
}

std::shared_ptr<midhook_wrapper> midhook_wrapper::create(void* target)
{
    if (!memory_utils::is_executable_pointer(target))
    {
        return nullptr;
    }

    if (std::any_of(midhooks.begin(), midhooks.end(), [target](const auto& hook_ptr) {
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

bool midhook_wrapper::has_ran_this_frame()
{
    int frame = current_frame.load(std::memory_order_relaxed);
    int prev = last_frame.exchange(frame, std::memory_order_relaxed);
    return frame == prev;
}

void midhook_wrapper::handle_offsets(general_purpose_register name, const uintptr_t base_reg, bool do_analysis)
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
        if (do_analysis)
        {
            item.second.report = pointer_analysis::analyze_pointer(item.second.value);
        }
    }
}

void midhook_wrapper::destination(SafetyHookContext& ctx)
{
    last_hit_time = std::chrono::steady_clock::now();
    hit_count++;
    bool do_analysis = show_live_window && !has_ran_this_frame();

#if SAFETYHOOK_ARCH_X86_32
    live_context[general_purpose_register::EAX].value = ctx.eax;
    live_context[general_purpose_register::ECX].value = ctx.ecx;
    live_context[general_purpose_register::EDX].value = ctx.edx;
    live_context[general_purpose_register::EBX].value = ctx.ebx;
    live_context[general_purpose_register::ESI].value = ctx.esi;
    live_context[general_purpose_register::EDI].value = ctx.edi;
    live_context[general_purpose_register::EBP].value = ctx.ebp;
    live_context[general_purpose_register::ESP].value = ctx.esp;
    live_control_context[control_register::EIP].value = ctx.eip;
    live_control_context[control_register::EFLAGS].value = ctx.eflags;
#elif SAFETYHOOK_ARCH_X86_64
    live_context[general_purpose_register::RAX].value = ctx.rax;
    live_context[general_purpose_register::RCX].value = ctx.rcx;
    live_context[general_purpose_register::RDX].value = ctx.rdx;
    live_context[general_purpose_register::RBX].value = ctx.rbx;
    live_context[general_purpose_register::RSI].value = ctx.rsi;
    live_context[general_purpose_register::RDI].value = ctx.rdi;
    live_context[general_purpose_register::RBP].value = ctx.rbp;
    live_context[general_purpose_register::RSP].value = ctx.rsp;
    live_context[general_purpose_register::R8].value = ctx.r8;
    live_context[general_purpose_register::R9].value = ctx.r9;
    live_context[general_purpose_register::R10].value = ctx.r10;
    live_context[general_purpose_register::R11].value = ctx.r11;
    live_context[general_purpose_register::R12].value = ctx.r12;
    live_context[general_purpose_register::R13].value = ctx.r13;
    live_context[general_purpose_register::R14].value = ctx.r14;
    live_context[general_purpose_register::R15].value = ctx.r15;
    live_control_context[control_register::RIP].value = ctx.rip;
    live_control_context[control_register::RFLAGS].value = ctx.rflags;
#endif

    live_xmm_context[0].value = ctx.xmm0;
    live_xmm_context[1].value = ctx.xmm1;
    live_xmm_context[2].value = ctx.xmm2;
    live_xmm_context[3].value = ctx.xmm3;
    live_xmm_context[4].value = ctx.xmm4;
    live_xmm_context[5].value = ctx.xmm5;
    live_xmm_context[6].value = ctx.xmm6;
    live_xmm_context[7].value = ctx.xmm7;
    ctx.xmm0 = live_xmm_context[0].do_override ? live_xmm_context[0].override_value : ctx.xmm0;
    ctx.xmm1 = live_xmm_context[1].do_override ? live_xmm_context[1].override_value : ctx.xmm1;
    ctx.xmm2 = live_xmm_context[2].do_override ? live_xmm_context[2].override_value : ctx.xmm2;
    ctx.xmm3 = live_xmm_context[3].do_override ? live_xmm_context[3].override_value : ctx.xmm3;
    ctx.xmm4 = live_xmm_context[4].do_override ? live_xmm_context[4].override_value : ctx.xmm4;
    ctx.xmm5 = live_xmm_context[5].do_override ? live_xmm_context[5].override_value : ctx.xmm5;
    ctx.xmm6 = live_xmm_context[6].do_override ? live_xmm_context[6].override_value : ctx.xmm6;
    ctx.xmm7 = live_xmm_context[7].do_override ? live_xmm_context[7].override_value : ctx.xmm7;
#if SAFETYHOOK_ARCH_X86_64
    live_xmm_context[8].value = ctx.xmm8;
    live_xmm_context[9].value = ctx.xmm9;
    live_xmm_context[10].value = ctx.xmm10;
    live_xmm_context[11].value = ctx.xmm11;
    live_xmm_context[12].value = ctx.xmm12;
    live_xmm_context[13].value = ctx.xmm13;
    live_xmm_context[14].value = ctx.xmm14;
    live_xmm_context[15].value = ctx.xmm15;
    ctx.xmm8 = live_xmm_context[8].do_override ? live_xmm_context[8].override_value : ctx.xmm8;
    ctx.xmm9 = live_xmm_context[9].do_override ? live_xmm_context[9].override_value : ctx.xmm9;
    ctx.xmm10 = live_xmm_context[10].do_override ? live_xmm_context[10].override_value : ctx.xmm10;
    ctx.xmm11 = live_xmm_context[11].do_override ? live_xmm_context[11].override_value : ctx.xmm11;
    ctx.xmm12 = live_xmm_context[12].do_override ? live_xmm_context[12].override_value : ctx.xmm12;
    ctx.xmm13 = live_xmm_context[13].do_override ? live_xmm_context[13].override_value : ctx.xmm13;
    ctx.xmm14 = live_xmm_context[14].do_override ? live_xmm_context[14].override_value : ctx.xmm14;
    ctx.xmm15 = live_xmm_context[15].do_override ? live_xmm_context[15].override_value : ctx.xmm15;
#endif

#if SAFETYHOOK_ARCH_X86_32
    ctx.eax = live_context[general_purpose_register::EAX].do_override
                  ? live_context[general_purpose_register::EAX].override_value
                  : ctx.eax;
    ctx.ecx = live_context[general_purpose_register::ECX].do_override
                  ? live_context[general_purpose_register::ECX].override_value
                  : ctx.ecx;
    ctx.edx = live_context[general_purpose_register::EDX].do_override
                  ? live_context[general_purpose_register::EDX].override_value
                  : ctx.edx;
    ctx.ebx = live_context[general_purpose_register::EBX].do_override
                  ? live_context[general_purpose_register::EBX].override_value
                  : ctx.ebx;
    ctx.esi = live_context[general_purpose_register::ESI].do_override
                  ? live_context[general_purpose_register::ESI].override_value
                  : ctx.esi;
    ctx.edi = live_context[general_purpose_register::EDI].do_override
                  ? live_context[general_purpose_register::EDI].override_value
                  : ctx.edi;
    ctx.ebp = live_context[general_purpose_register::EBP].do_override
                  ? live_context[general_purpose_register::EBP].override_value
                  : ctx.ebp;
    ctx.trampoline_esp = live_context[general_purpose_register::ESP].do_override
                             ? live_context[general_purpose_register::ESP].override_value
                             : ctx.trampoline_esp;
    ctx.eip = live_control_context[control_register::EIP].do_override
                  ? live_control_context[control_register::EIP].override_value
                  : ctx.eip;
    ctx.eflags = live_control_context[control_register::EFLAGS].do_override
                     ? live_control_context[control_register::EFLAGS].override_value
                     : ctx.eflags;
#elif SAFETYHOOK_ARCH_X86_64
    ctx.rax = live_context[general_purpose_register::RAX].do_override
                  ? live_context[general_purpose_register::RAX].override_value
                  : ctx.rax;
    ctx.rcx = live_context[general_purpose_register::RCX].do_override
                  ? live_context[general_purpose_register::RCX].override_value
                  : ctx.rcx;
    ctx.rdx = live_context[general_purpose_register::RDX].do_override
                  ? live_context[general_purpose_register::RDX].override_value
                  : ctx.rdx;
    ctx.rbx = live_context[general_purpose_register::RBX].do_override
                  ? live_context[general_purpose_register::RBX].override_value
                  : ctx.rbx;
    ctx.rsi = live_context[general_purpose_register::RSI].do_override
                  ? live_context[general_purpose_register::RSI].override_value
                  : ctx.rsi;
    ctx.rdi = live_context[general_purpose_register::RDI].do_override
                  ? live_context[general_purpose_register::RDI].override_value
                  : ctx.rdi;
    ctx.rbp = live_context[general_purpose_register::RBP].do_override
                  ? live_context[general_purpose_register::RBP].override_value
                  : ctx.rbp;
    ctx.rsp = live_context[general_purpose_register::RSP].do_override
                  ? live_context[general_purpose_register::RSP].override_value
                  : ctx.rsp;
    ctx.r8 = live_context[general_purpose_register::R8].do_override
                 ? live_context[general_purpose_register::R8].override_value
                 : ctx.r8;
    ctx.r9 = live_context[general_purpose_register::R9].do_override
                 ? live_context[general_purpose_register::R9].override_value
                 : ctx.r9;
    ctx.r10 = live_context[general_purpose_register::R10].do_override
                  ? live_context[general_purpose_register::R10].override_value
                  : ctx.r10;
    ctx.r11 = live_context[general_purpose_register::R11].do_override
                  ? live_context[general_purpose_register::R11].override_value
                  : ctx.r11;
    ctx.r12 = live_context[general_purpose_register::R12].do_override
                  ? live_context[general_purpose_register::R12].override_value
                  : ctx.r12;
    ctx.r13 = live_context[general_purpose_register::R13].do_override
                  ? live_context[general_purpose_register::R13].override_value
                  : ctx.r13;
    ctx.r14 = live_context[general_purpose_register::R14].do_override
                  ? live_context[general_purpose_register::R14].override_value
                  : ctx.r14;
    ctx.r15 = live_context[general_purpose_register::R15].do_override
                  ? live_context[general_purpose_register::R15].override_value
                  : ctx.r15;
    ctx.rip = live_control_context[control_register::RIP].do_override
                  ? live_control_context[control_register::RIP].override_value
                  : ctx.rip;
    ctx.rflags = live_control_context[control_register::RFLAGS].do_override
                     ? live_control_context[control_register::RFLAGS].override_value
                     : ctx.rflags;
#endif

    if (do_analysis)
    {
        analysis_count++;
#if SAFETYHOOK_ARCH_X86_32
        live_context[general_purpose_register::EAX].report = pointer_analysis::analyze_pointer(ctx.eax);
        live_context[general_purpose_register::ECX].report = pointer_analysis::analyze_pointer(ctx.ecx);
        live_context[general_purpose_register::EDX].report = pointer_analysis::analyze_pointer(ctx.edx);
        live_context[general_purpose_register::EBX].report = pointer_analysis::analyze_pointer(ctx.ebx);
        live_context[general_purpose_register::ESI].report = pointer_analysis::analyze_pointer(ctx.esi);
        live_context[general_purpose_register::EDI].report = pointer_analysis::analyze_pointer(ctx.edi);
        live_context[general_purpose_register::EBP].report = pointer_analysis::analyze_pointer(ctx.ebp);
        live_context[general_purpose_register::ESP].report = pointer_analysis::analyze_pointer(ctx.esp);
#elif SAFETYHOOK_ARCH_X86_64
        live_context[general_purpose_register::RAX].report = pointer_analysis::analyze_pointer(ctx.rax);
        live_context[general_purpose_register::RCX].report = pointer_analysis::analyze_pointer(ctx.rcx);
        live_context[general_purpose_register::RDX].report = pointer_analysis::analyze_pointer(ctx.rdx);
        live_context[general_purpose_register::RBX].report = pointer_analysis::analyze_pointer(ctx.rbx);
        live_context[general_purpose_register::RSI].report = pointer_analysis::analyze_pointer(ctx.rsi);
        live_context[general_purpose_register::RDI].report = pointer_analysis::analyze_pointer(ctx.rdi);
        live_context[general_purpose_register::RBP].report = pointer_analysis::analyze_pointer(ctx.rbp);
        live_context[general_purpose_register::RSP].report = pointer_analysis::analyze_pointer(ctx.rsp);
        live_context[general_purpose_register::R8].report = pointer_analysis::analyze_pointer(ctx.r8);
        live_context[general_purpose_register::R9].report = pointer_analysis::analyze_pointer(ctx.r9);
        live_context[general_purpose_register::R10].report = pointer_analysis::analyze_pointer(ctx.r10);
        live_context[general_purpose_register::R11].report = pointer_analysis::analyze_pointer(ctx.r11);
        live_context[general_purpose_register::R12].report = pointer_analysis::analyze_pointer(ctx.r12);
        live_context[general_purpose_register::R13].report = pointer_analysis::analyze_pointer(ctx.r13);
        live_context[general_purpose_register::R14].report = pointer_analysis::analyze_pointer(ctx.r14);
        live_context[general_purpose_register::R15].report = pointer_analysis::analyze_pointer(ctx.r15);
#endif
    }

#if SAFETYHOOK_ARCH_X86_32
    handle_offsets(general_purpose_register::EAX, ctx.eax, do_analysis);
    handle_offsets(general_purpose_register::ECX, ctx.ecx, do_analysis);
    handle_offsets(general_purpose_register::EDX, ctx.edx, do_analysis);
    handle_offsets(general_purpose_register::EBX, ctx.ebx, do_analysis);
    handle_offsets(general_purpose_register::ESI, ctx.esi, do_analysis);
    handle_offsets(general_purpose_register::EDI, ctx.edi, do_analysis);
    handle_offsets(general_purpose_register::EBP, ctx.ebp, do_analysis);
    handle_offsets(general_purpose_register::ESP, ctx.esp, do_analysis);
#elif SAFETYHOOK_ARCH_X86_64
    handle_offsets(general_purpose_register::RAX, ctx.rax, do_analysis);
    handle_offsets(general_purpose_register::RCX, ctx.rcx, do_analysis);
    handle_offsets(general_purpose_register::RDX, ctx.rdx, do_analysis);
    handle_offsets(general_purpose_register::RBX, ctx.rbx, do_analysis);
    handle_offsets(general_purpose_register::RSI, ctx.rsi, do_analysis);
    handle_offsets(general_purpose_register::RDI, ctx.rdi, do_analysis);
    handle_offsets(general_purpose_register::RBP, ctx.rbp, do_analysis);
    handle_offsets(general_purpose_register::RSP, ctx.rsp, do_analysis);
    handle_offsets(general_purpose_register::R8, ctx.r8, do_analysis);
    handle_offsets(general_purpose_register::R9, ctx.r9, do_analysis);
    handle_offsets(general_purpose_register::R10, ctx.r10, do_analysis);
    handle_offsets(general_purpose_register::R11, ctx.r11, do_analysis);
    handle_offsets(general_purpose_register::R12, ctx.r12, do_analysis);
    handle_offsets(general_purpose_register::R13, ctx.r13, do_analysis);
    handle_offsets(general_purpose_register::R14, ctx.r14, do_analysis);
    handle_offsets(general_purpose_register::R15, ctx.r15, do_analysis);
#endif
}

void midhook_wrapper::trampoline(SafetyHookContext& ctx)
{
    if (auto it = registry.find(ctx.IP_REG); it != registry.end() && it->second)
    {
        it->second->destination(ctx);
    }
}
