#pragma once
#include <chrono>
#include <safetyhook.hpp>
#include "safetyhook/ContextEx.h"

class midhook_wrapper
{
public:
    inline static std::vector<std::shared_ptr<midhook_wrapper>> midhooks;

    SafetyHookMid hook;

    std::chrono::steady_clock::time_point last_hit_time{};
    size_t hit_amount = 0;
    bool show_live_window = false;
    safetyhook::ContextEx last_context{};

    static std::shared_ptr<midhook_wrapper> create(void* target);

    explicit midhook_wrapper(SafetyHookMid internal_hook);
    ~midhook_wrapper();
   

    inline const safetyhook::Allocation& get_trampoline() const;
    
private:
    inline static std::unordered_map<uintptr_t, midhook_wrapper*> registry; // trampoline_address, this*

    void destination(SafetyHookContext& ctx);
    static void trampoline(SafetyHookContext& ctx);
};
