#pragma once
#include "memory_utils.h"

namespace gui::midhook::entry::live
{
    void draw_analysis(const memory_utils::pointer_analysis_report& report)
    {
        if (!report.is_readable_ptr)
        {
            return;
        }

        ImGui::PushID("ptr_analysis");

        std::stringstream ss;
        ss << std::hex << std::uppercase;

        ss << " -> ";

        if (report.points_to.has_value())
        {
            ss << "0x" << report.points_to.value() << "  ";
        }

        

        if (report.as_float.has_value())
        {
            ss << "float(" << report.as_float.value() << ") ";
        }

        if (report.as_double.has_value())
        {
            ss << "double(" << report.as_double.value() << ") ";
        }

        if (!report.as_string.empty())
        {
            ss << "string(" << report.as_string << ") ";
        }

        ImGui::SameLine();
        ImGui::Text("%s", ss.str().c_str());

        ImGui::PopID();
    }

    void draw_register(const std::string& name, uintptr_t reg, const memory_utils::pointer_analysis_report* report, bool* do_override_reg, uintptr_t* override_reg, bool is_hook_enabled)
    {
        ImGui::PushID(name.c_str());

        ImGui::Text((name + ": ").c_str());

        ImGui::BeginDisabled(!*do_override_reg);

        std::string hex_str = std::format("0x{:0{}X}", *do_override_reg ? *override_reg : reg , sizeof(uintptr_t) * 2);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        ImGui::InputText("##", hex_str.data(), hex_str.capacity() + 1, *do_override_reg ? 0 : ImGuiInputTextFlags_ReadOnly);

        ImGui::EndDisabled();
        if (*do_override_reg)
        {
            unsigned long long addr = 0;
            try
            {
                addr = std::stoull(hex_str, nullptr, 16);
            }
            catch (...) {}
            *override_reg = addr;
        }

        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        {
            ImGui::BeginTooltip();
            ImGui::Text("dec: %llu", static_cast<unsigned long long>(reg));
            ImGui::EndTooltip();
        }

        ImGui::BeginDisabled(is_hook_enabled && !*do_override_reg);
        ImGui::SameLine();
        ImGui::Checkbox("Override", do_override_reg);
        ImGui::EndDisabled();

        if (report)
        {
            draw_analysis(*report);
        }

        ImGui::PopID();
    }

	void draw(midhook_wrapper& hook)
	{
        ImGui::SetNextWindowSize(ImVec2(0, 0), ImGuiCond_FirstUseEver);
		if (ImGui::Begin(std::format("Live 0x{:X} View", hook.hook.target_address()).c_str(), &hook.show_live_window, ImGuiWindowFlags_AlwaysAutoResize))
		{
            flash_row_background(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - hook.last_hit_time).count());

            bool enabled = hook.hook.enabled();
            if (ImGui::Checkbox("Enabled", &enabled))
            {
                enabled ? hook.hook.enable() : hook.hook.disable();
            }
            ImGui::Separator();


            auto& ctx = hook.get_last_context();

#if SAFETYHOOK_ARCH_X86_64
            draw_register("RAX", ctx.rax);
            draw_register("RBX", ctx.rbx);
            draw_register("RCX", ctx.rcx);
            draw_register("RDX", ctx.rdx);
            draw_register("RSI", ctx.rsi);
            draw_register("RDI", ctx.rdi);
            draw_register("RBP", ctx.rbp);
            draw_register("RSP", ctx.rsp);
            draw_register("R8", ctx.r8);
            draw_register("R9", ctx.r9);
            draw_register("R10", ctx.r10);
            draw_register("R11", ctx.r11);
            draw_register("R12", ctx.r12);
            draw_register("R13", ctx.r13);
            draw_register("R14", ctx.r14);
            draw_register("R15", ctx.r15);
            draw_register("RIP", ctx.rip);
#else
            draw_register("EAX", ctx.get_context().eax, &ctx.eax_report, &hook.context_override.override_eax, &hook.context_override.eax, hook.hook.enabled());
            draw_register("EBX", ctx.get_context().ebx, &ctx.ebx_report, &hook.context_override.override_ebx, &hook.context_override.ebx, hook.hook.enabled());
            draw_register("ECX", ctx.get_context().ecx, &ctx.ecx_report, &hook.context_override.override_ecx, &hook.context_override.ecx, hook.hook.enabled());
            draw_register("EDX", ctx.get_context().edx, &ctx.edx_report, &hook.context_override.override_edx, &hook.context_override.edx, hook.hook.enabled());
            draw_register("ESI", ctx.get_context().esi, &ctx.esi_report, &hook.context_override.override_esi, &hook.context_override.esi, hook.hook.enabled());
            draw_register("EDI", ctx.get_context().edi, &ctx.edi_report, &hook.context_override.override_edi, &hook.context_override.edi, hook.hook.enabled());
            draw_register("EBP", ctx.get_context().ebp, &ctx.ebp_report, &hook.context_override.override_ebp, &hook.context_override.ebp, hook.hook.enabled());
            draw_register("ESP", ctx.get_context().esp, &ctx.esp_report, &hook.context_override.override_esp, &hook.context_override.esp, hook.hook.enabled());
            draw_register("EIP", ctx.get_context().eip, nullptr, &hook.context_override.override_eip, &hook.context_override.eip, hook.hook.enabled());

            ImGui::BeginDisabled(hook.hook.enabled());
            ImGui::SameLine();
            if (ImGui::Button("Set Trampoline to next RET"))
            {
                if (auto ret_location = memory_utils::find_next_mnemonic(hook.hook.target_address(), ZYDIS_MNEMONIC_RET))
                {
                    hook.context_override.eip = ret_location;
                    hook.context_override.override_eip = true;
                }
                else
                {
                    reshade::log::message(reshade::log::level::error, "Could not find next ret instruction");
                }
            }
            ImGui::EndDisabled();

            draw_register("EFL", ctx.get_context().eflags, nullptr, &hook.context_override.override_eflags, &hook.context_override.eflags, hook.hook.enabled());
#endif
		}
		ImGui::End();
	}
}

