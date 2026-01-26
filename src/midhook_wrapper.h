#pragma once
#include <chrono>
#include <safetyhook.hpp>
#include "context_wrapper.h"

class midhook_wrapper
{
public:
    inline static std::vector<std::shared_ptr<midhook_wrapper>> midhooks;

    SafetyHookMid hook;

    std::chrono::steady_clock::time_point last_hit_time{};
    size_t hit_amount = 0;
    bool show_live_window = false;
    

    static std::shared_ptr<midhook_wrapper> create(void* target);

    explicit midhook_wrapper(SafetyHookMid internal_hook);
    ~midhook_wrapper();
   

    inline const safetyhook::Allocation& get_trampoline() const;
    
    inline const context_wrapper& get_last_context() const
    {
        return last_context;
    }

    struct override_context : safetyhook::Context
    {
#if SAFETYHOOK_ARCH_X86_64
        bool override_rflags, override_r15, override_r14, override_r13, override_r12, override_r11, override_r10, override_r9, override_r8, override_rdi, override_rsi, override_rdx, override_rcx, override_rbx, override_rax, override_rbp, override_rsp, override_rip;
#elif SAFETYHOOK_ARCH_X86_32
        bool override_eflags, override_edi, override_esi, override_edx, override_ecx, override_ebx, override_eax, override_ebp, override_esp, override_eip;
#endif
    };

    override_context context_override{};

private:
    context_wrapper last_context{};
    inline static std::unordered_map<uintptr_t, midhook_wrapper*> registry; // trampoline_address, this*

    void destination(SafetyHookContext& ctx);
    static void trampoline(SafetyHookContext& ctx);
};
