#include "memory_utils.h"

namespace memory_utils
{
    pointer_analysis_report analyze_pointer(uintptr_t addr)
    {
        pointer_analysis_report result{};
        result.pointer = addr;
        result.as_float = nullptr;
        result.as_double = nullptr;
        result.as_string.clear();
        result.is_valid_ptr = is_readable_pointer(addr);

        if (!result.is_valid_ptr)
            return result;

        float tmp_float{};
        const bool float_ok = (addr & (alignof(float) - 1)) == 0 && safe_read(addr, tmp_float);
        result.as_float = float_ok ? reinterpret_cast<float*>(addr) : nullptr;

        double tmp_double{};
        const bool double_ok = (addr & (alignof(double) - 1)) == 0 && safe_read(addr, tmp_double);
        result.as_double = double_ok ? reinterpret_cast<double*>(addr) : nullptr;

        safe_read_string(addr, result.as_string);

        return result;
    }

    bool is_executable_pointer(const void* ptr)
    {
        uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);

        if (!looks_like_pointer(addr)) return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;

        constexpr DWORD executable_flags =
            PAGE_EXECUTE |
            PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE |
            PAGE_EXECUTE_WRITECOPY;

        return (mbi.Protect & executable_flags) != 0;
    }

    bool safe_read_string(uintptr_t addr, std::string& out, bool replace_line_endings)
    {
        if (!looks_like_pointer(addr))
            return false;

        out.clear();
        out.reserve(MAX_STRING_LEN);

        __try
        {
            const char* p = reinterpret_cast<const char*>(addr);
            for (size_t i = 0; i < MAX_STRING_LEN; ++i)
            {
                char c = p[i];
                if (c == '\0') break;

                if (replace_line_endings && (c == '\n' || c == '\r'))
                {
                    out.append(c == '\n' ? "\\n" : "\\r");
                    continue;
                }

                if (std::isprint(static_cast<unsigned char>(c)))
                {
                    out.push_back(c);
                }
                else
                {
                    return false;
                }
            }
            return !out.empty();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
}
