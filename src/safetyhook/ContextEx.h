#pragma once
#include <string>
#include <safetyhook.hpp>
#include "memory_utils.h"

namespace safetyhook
{
    struct ContextEx
    {
    public:
        Context ctx{};

        ContextEx(Context internal_ctx, bool do_generate_report = false) : ctx(internal_ctx)
        {
            if (do_generate_report)
            {
                generate_report();
            }
        }

        ContextEx(){}
        
        memory_utils::pointer_analysis_report edi_report{};
        memory_utils::pointer_analysis_report esi_report{};
        memory_utils::pointer_analysis_report edx_report{};
        memory_utils::pointer_analysis_report ecx_report{};
        memory_utils::pointer_analysis_report ebx_report{};
        memory_utils::pointer_analysis_report eax_report{};
        memory_utils::pointer_analysis_report ebp_report{};
        memory_utils::pointer_analysis_report esp_report{};

    private:
        bool already_generated_report = false;
        inline void generate_report()
        {
            if (already_generated_report)
                return;

            eax_report = memory_utils::analyze_pointer(ctx.eax);
            ebx_report = memory_utils::analyze_pointer(ctx.ebx);
            ecx_report = memory_utils::analyze_pointer(ctx.ecx);
            edx_report = memory_utils::analyze_pointer(ctx.edx);
            esi_report = memory_utils::analyze_pointer(ctx.esi);
            edi_report = memory_utils::analyze_pointer(ctx.edi);
            ebp_report = memory_utils::analyze_pointer(ctx.ebp);
            esp_report = memory_utils::analyze_pointer(ctx.esp);
            already_generated_report = true;
        }
    };
}
