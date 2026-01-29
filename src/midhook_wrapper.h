#pragma once
#include <chrono>
#include <safetyhook.hpp>
#include <map>
#include <pointer_analysis.h>


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
    
    struct register_definition
    {
        uintptr_t value = 0x0;
        pointer_analysis::report report{};
        bool do_override = false;
        uintptr_t override_value = 0x0;
    };

    std::map<const char*, register_definition> live_context;

    inline const safetyhook::Allocation& get_trampoline() const;
private:
    inline static std::unordered_map<uintptr_t, midhook_wrapper*> registry; // trampoline_address, this*

    void init_live_context();

    void destination(SafetyHookContext& ctx);
    static void trampoline(SafetyHookContext& ctx);
};
