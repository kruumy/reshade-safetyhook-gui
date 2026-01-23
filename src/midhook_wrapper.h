#pragma once
#include <chrono>
#include <safetyhook.hpp>

class midhook_wrapper
{
public:

    SafetyHookMid hook;

    std::chrono::steady_clock::time_point last_hit_time{};
    static constexpr size_t MAX_LOG_SIZE = 100 * 1024;
    bool show_log_window = false;

    explicit midhook_wrapper(void* target);
    ~midhook_wrapper();

    inline std::string_view get_log() const { return log.view(); }
    inline void clear_log() { log.str(""); log.clear(); }

    inline const safetyhook::Allocation& get_trampoline() const;

private:

    inline static std::unordered_map<uintptr_t, midhook_wrapper*> registry;
    std::stringstream log;

    void destination(SafetyHookContext& ctx);
    static void trampoline(SafetyHookContext& ctx);
};
