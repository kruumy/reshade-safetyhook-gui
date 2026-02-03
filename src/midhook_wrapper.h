#pragma once
#include <chrono>
#include <safetyhook.hpp>
#include <pointer_analysis.h>
#include <array>
#include <atomic>

class midhook_wrapper
{
public:
    enum general_purpose_register
    {
#if SAFETYHOOK_ARCH_X86_32
        EAX,
        ECX,
        EDX,
        EBX,
        ESI,
        EDI,
        EBP,
        ESP,
#elif SAFETYHOOK_ARCH_X86_64
        RAX,
        RCX,
        RDX,
        RBX,
        RSI,
        RDI,
        RBP,
        RSP,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
#endif
        general_purpose_COUNT
    };

    enum xmm_register
    {
        XMM0,
        XMM1,
        XMM2,
        XMM3,
        XMM4,
        XMM5,
        XMM6,
        XMM7,
#if SAFETYHOOK_ARCH_X86_64
        XMM8,
        XMM9,
        XMM10,
        XMM11,
        XMM12,
        XMM13,
        XMM14,
        XMM15,
#endif
        xmm_COUNT
    };
    enum control_register
    {
#if SAFETYHOOK_ARCH_X86_32
        EIP,
        EFLAGS,
#elif SAFETYHOOK_ARCH_X86_64
        RIP,
        RFLAGS,
#endif
        control_COUNT
    };

    inline static std::vector<std::shared_ptr<midhook_wrapper>> midhooks;

    SafetyHookMid hook;

    std::chrono::steady_clock::time_point last_hit_time{};
    size_t hit_amount = 0;
    size_t analysis_count = 0;

    bool show_live_window = false;
    

    static std::shared_ptr<midhook_wrapper> create(void* target);

    explicit midhook_wrapper(SafetyHookMid internal_hook);
    ~midhook_wrapper();
    
    struct control_register_definition
    {
        uintptr_t value = 0x0;
        bool do_override = false;
        uintptr_t override_value = 0x0;
    };

    struct offset_register_definition : control_register_definition
    {
        pointer_analysis::report report{};
    };

    struct general_purpose_register_definition : offset_register_definition
    {
        std::vector<std::pair<int, offset_register_definition>> offset_definitions;
    };

    struct xmm_register_definition
    {
        safetyhook::Xmm value{};
        bool do_override = false;
        safetyhook::Xmm override_value{};
    };

    std::array<general_purpose_register_definition, general_purpose_register::general_purpose_COUNT> live_context;
    std::array<control_register_definition, control_register::control_COUNT> live_control_context;
    std::array<xmm_register_definition, xmm_register::xmm_COUNT> live_xmm_context;

    inline const safetyhook::Allocation& get_trampoline() const;
    void on_imgui_render();
private:
    std::atomic<int> current_frame{ 0 };
    std::atomic<int> last_frame{ -1 };
    bool has_ran_this_frame();
    inline static std::unordered_map<uintptr_t, midhook_wrapper*> registry; // trampoline_address, this*

    void handle_offsets(general_purpose_register name, const uintptr_t base_reg, bool do_analysis);

    void destination(SafetyHookContext& ctx);
    static void trampoline(SafetyHookContext& ctx);
};
