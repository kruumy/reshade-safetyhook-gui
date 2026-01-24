#pragma once
#include <chrono>
#include <safetyhook.hpp>

class midhook_wrapper
{
public:
    inline static std::vector<std::shared_ptr<midhook_wrapper>> midhooks;

    SafetyHookMid hook;

    std::chrono::steady_clock::time_point last_hit_time{};
    static constexpr size_t MAX_LOG_SIZE = 100 * 1024;
    size_t hit_amount = 0;
    bool show_log_window = false;
    bool show_live_window = false;
    SafetyHookContext last_context{};

    static std::shared_ptr<midhook_wrapper> create(void* target);

    explicit midhook_wrapper(SafetyHookMid internal_hook);
    ~midhook_wrapper();
    
    inline std::string_view get_log() const { return log.view(); }
    inline void clear_log() { log.str(""); log.clear(); }

    inline const safetyhook::Allocation& get_trampoline() const;
    
private:
    inline static std::unordered_map<uintptr_t, midhook_wrapper*> registry; // trampoline_address, this*
    std::stringstream log;

    void destination(SafetyHookContext& ctx);
    static void trampoline(SafetyHookContext& ctx);
};
