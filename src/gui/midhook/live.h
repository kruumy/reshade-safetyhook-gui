#pragma once
#include "memory_utils.h"

namespace gui::midhook::live
{
    void draw_analysis(const pointer_analysis::report& report)
    {
        if (!report.is_readable_ptr())
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

    bool draw_offset(const std::string& name, bool is_hook_enabled, size_t i, std::vector<std::pair<int, midhook_wrapper::offset_register_definition>>& offset_definitions)
    {
        ImGui::PushID(static_cast<int>(i));
        auto& reg = offset_definitions[i];

        if (ImGui::Button("-"))
        {
            offset_definitions.erase(offset_definitions.begin() + i);
            ImGui::PopID();
            return false;
        }

        ImGui::SameLine();
        ImGui::Text((name + " +").c_str());

        ImGui::SameLine();
        ImGui::SetNextItemWidth(75);
        ImGui::InputInt(("##offset_" + name + "_" + std::to_string(i)).c_str(), &reg.first, 1, sizeof(void*),
            (is_hook_enabled && reg.second.do_override) ? ImGuiInputTextFlags_ReadOnly : 0);

        ImGui::SameLine();
        ImGui::Text(": ");

        ImGui::SameLine();
        ImGui::Text("%s", std::format("0x{:0{}X}", reg.second.value, sizeof(void*) * 2).c_str());

        if (reg.second.report.as_uintptr.has_value())
        {
            ImGui::SameLine();
            ImGui::Text(" -> ");

            ImGui::BeginDisabled(!reg.second.do_override);
            std::string hex_str = std::format("0x{:0{}X}", reg.second.do_override ? reg.second.override_value : reg.second.report.as_uintptr.value(), sizeof(void*) * 2);
            ImGui::SameLine();
            ImGui::SetNextItemWidth(ImGui::CalcTextSize(hex_str.c_str()).x + ImGui::GetStyle().FramePadding.x * 2.0f);
            ImGui::InputText("##", hex_str.data(), hex_str.capacity() + 1, reg.second.do_override ? 0 : ImGuiInputTextFlags_ReadOnly);
            ImGui::EndDisabled();

            if (reg.second.do_override)
            {
                unsigned long long addr = 0;
                try
                {
                    addr = std::stoull(hex_str, nullptr, 16);
                }
                catch (...) {}
                reg.second.override_value = addr;
            }

            ImGui::BeginDisabled(is_hook_enabled && !reg.second.do_override);
            ImGui::SameLine();
            ImGui::Checkbox("Override", &reg.second.do_override);
            ImGui::EndDisabled();
        }

        draw_analysis(reg.second.report);

        ImGui::PopID();
        return true;
    }

    void draw_offsets(const std::string& name, midhook_wrapper::register_definition& reg, bool is_hook_enabled)
    {
        constexpr float INDENT = 32.0f;

        ImGui::PushID(name.c_str());
        ImGui::Indent(INDENT);

        for (size_t i = 0; i < reg.offset_definitions.size();)
        {
            
            if (draw_offset(name, is_hook_enabled, i, reg.offset_definitions))
            {
                ++i;
            }
        }

        if (ImGui::Button("+"))
        {
            reg.offset_definitions.emplace_back(
                static_cast<int>(sizeof(void*)),
                midhook_wrapper::offset_register_definition{}
            );
        }

        ImGui::Unindent(INDENT);
        ImGui::PopID();
    }

    void draw_register_and_offsets(const std::string& name, midhook_wrapper::register_definition& reg, bool is_hook_enabled)
    {
        ImGui::Separator();
        draw_register(name, reg, is_hook_enabled);
        draw_offsets(name, reg, is_hook_enabled);
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

            ImGui::SameLine();
            ImGui::Text("Hits: %d", hook.hit_amount);

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
            draw_register_and_offsets("EIP", hook.live_context["EIP"], hook.hook.enabled());
#endif
		}
		ImGui::End();
	}
}

