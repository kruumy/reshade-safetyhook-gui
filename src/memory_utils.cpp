#include "memory_utils.h"

namespace memory_utils
{
    pointer_analysis_report analyze_pointer(uintptr_t addr)
    {
        pointer_analysis_report r{};
        r.pointer = addr;
        r.is_readable_ptr = is_readable_pointer(addr);

        if (!r.is_readable_ptr)
            return r;

        uintptr_t target = 0;
        if (safe_read(addr, target))
        {
            r.points_to = target;
        }
        {
            alignas(4) float f{};
            if ((addr & 3) == 0 && safe_read(addr, f))
                r.as_float = f;
        }
        {
            alignas(8) double d{};
            if ((addr & 7) == 0 && safe_read(addr, d))
                r.as_double = d;
        }
        safe_read_string(addr, r.as_string);

        return r;
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

    uintptr_t find_next_mnemonic(uintptr_t start_addr, ZydisMnemonic target_mnemonic) 
    {
        ZydisDecoder decoder;
        ZydisDecodedInstruction ix;

#if SAFETYHOOK_ARCH_X86_64
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#endif
        const ZyanUSize max_length = 4096;
        ZyanUSize offset = 0;
        while (offset < max_length) 
        {
            ZyanStatus status = ZydisDecoderDecodeInstruction(&decoder, NULL, reinterpret_cast<const uint8_t*>(start_addr) + offset, max_length - offset, &ix);
            if (!ZYAN_SUCCESS(status) || ix.length == 0) 
            {
                return 0;
            }
            if (ix.mnemonic == target_mnemonic) 
            {
                return start_addr + offset;
            }
            offset += ix.length;
        }
        return 0;
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
