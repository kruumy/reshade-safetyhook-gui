#pragma once
#include "memory_utils.h"

namespace gui::midhook::entry::live
{
    void draw_analysis(const pointer_analysis::report& report)
    {
        if (!report.is_readable_ptr)
        {
            return;
        }

        ImGui::PushID("ptr_analysis");

        std::stringstream ss;
        ss << std::hex << std::uppercase;

        ss << " -> ";

        if (report.as_uintptr.has_value())
        {
            ss << "0x" << report.as_uintptr.value() << "  ";
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

    void draw_register(const std::string& name, midhook_wrapper::offset_register_definition& reg, bool is_hook_enabled)
    {
        ImGui::PushID(name.c_str());

        ImGui::Text((name + ": ").c_str());

        ImGui::BeginDisabled(!reg.do_override);

        std::string hex_str = std::format("0x{:0{}X}", reg.do_override ? reg.override_value : reg.value, sizeof(void*) * 2);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        ImGui::InputText("##", hex_str.data(), hex_str.capacity() + 1, reg.do_override ? 0 : ImGuiInputTextFlags_ReadOnly);

        ImGui::EndDisabled();
        if (reg.do_override)
        {
            unsigned long long addr = 0;
            try
            {
                addr = std::stoull(hex_str, nullptr, 16);
            }
            catch (...) {}
            reg.override_value = addr;
        }

        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        {
            ImGui::BeginTooltip();
            ImGui::Text("dec: %llu", static_cast<unsigned long long>(reg.value));
            ImGui::EndTooltip();
        }

        ImGui::BeginDisabled(is_hook_enabled && !reg.do_override);
        ImGui::SameLine();
        ImGui::Checkbox("Override", &reg.do_override);
        ImGui::EndDisabled();

        draw_analysis(reg.report);

        ImGui::PopID();
    }

    void draw_register_and_offsets(const std::string& name, midhook_wrapper::register_definition& reg, bool is_hook_enabled)
    {
        ImGui::PushID(name.c_str());
        draw_register(name, reg, is_hook_enabled);
        ImGui::SameLine();
        if (ImGui::Button("+"))
        {
            reg.offset_definitions.push_back(std::pair<int, midhook_wrapper::offset_register_definition>(sizeof(void*), midhook_wrapper::offset_register_definition{}));
        }
        for (auto& offset_register : reg.offset_definitions)
        {
            ImGui::Dummy(ImVec2(25, 0));

            ImGui::SetNextItemWidth(75);
            ImGui::SameLine();
            ImGui::InputInt(("##offset_" + name + "_" + std::to_string(offset_register.first)).c_str(), &offset_register.first, 1, sizeof(void*));
            ImGui::SameLine();
            draw_register(name + " + " + std::to_string(offset_register.first), offset_register.second, is_hook_enabled);
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

#if SAFETYHOOK_ARCH_X86_64
    //TODO x64
#else
            draw_register_and_offsets("EAX", hook.live_context["EAX"], hook.hook.enabled());
            draw_register_and_offsets("ECX", hook.live_context["ECX"], hook.hook.enabled());
            draw_register_and_offsets("EDX", hook.live_context["EDX"], hook.hook.enabled());
            draw_register_and_offsets("EBX", hook.live_context["EBX"], hook.hook.enabled());
            draw_register_and_offsets("ESI", hook.live_context["ESI"], hook.hook.enabled());
            draw_register_and_offsets("EDI", hook.live_context["EDI"], hook.hook.enabled());
            draw_register_and_offsets("EBP", hook.live_context["EBP"], hook.hook.enabled());
            draw_register_and_offsets("ESP", hook.live_context["ESP"], hook.hook.enabled());

            draw_register("EIP", hook.live_context["EIP"], hook.hook.enabled());
            ImGui::BeginDisabled(hook.hook.enabled());
            ImGui::SameLine();
            if (ImGui::Button("Set Trampoline to next RET"))
            {
                if (auto ret_location = memory_utils::find_next_mnemonic(hook.hook.target_address(), ZYDIS_MNEMONIC_RET))
                {
                    hook.live_context["EIP"].override_value = ret_location;
                    hook.live_context["EIP"].do_override = true;
                }
                else
                {
                    reshade::log::message(reshade::log::level::error, "Could not find next ret instruction");
                }
            }
            ImGui::EndDisabled();
#endif

		}
		ImGui::End();
	}
}

