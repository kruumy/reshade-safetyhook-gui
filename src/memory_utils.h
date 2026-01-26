#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <Zydis/Zydis.h>

namespace memory_utils
{
    static constexpr size_t    MAX_STRING_LEN = 64;
    static constexpr uintptr_t LOW_PTR = 0x10000;
#if defined(_WIN64)
    static constexpr uintptr_t HI_PTR = 0x00007FFFFFFFFFFF;
#endif

    static inline bool looks_like_pointer(uintptr_t v)
    {
        if (!v) return false;
#if defined(_WIN64)
        return v >= LOW_PTR && v <= HI_PTR;
#else
        return v >= LOW_PTR;
#endif
    }

    

    template <typename T>
    static inline bool safe_read(uintptr_t addr, T& out)
    {
        if (!looks_like_pointer(addr)) return false;

        __try
        {
            std::memcpy(&out, reinterpret_cast<const void*>(addr), sizeof(T));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    static inline bool is_readable_pointer(uintptr_t addr)
    {
        if (!looks_like_pointer(addr)) return false;

        uint8_t probe;
        return safe_read(addr, probe);
    }

    bool safe_read_string(uintptr_t addr, std::string& out, bool replace_line_endings = true);

    struct pointer_analysis_report
    {
        uintptr_t pointer;
        bool is_valid_ptr;
        float* as_float;
        double* as_double;
        std::string as_string;
    };

    pointer_analysis_report analyze_pointer(uintptr_t addr);

    static inline pointer_analysis_report analyze_pointer(void* ptr)
    {
        return analyze_pointer(reinterpret_cast<uintptr_t>(ptr));
    }

    bool is_executable_pointer(const void* ptr);
    uintptr_t find_next_mnemonic(uintptr_t start_addr, ZydisMnemonic target_mnemonic);
}
