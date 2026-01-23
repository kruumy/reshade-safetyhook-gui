#pragma once
#include <imgui.h>
#include <reshade.hpp>
#include "hook_manager.h"
#include <string>
#include <vector>

namespace gui
{
	void draw_inlinehook(inlinehook_definition& hook, size_t index)
	{

	}

	void draw_inlinehook_section()
	{
		ImGui::PushID("inlinehook");

		ImGui::PushItemWidth(100);
		static int calling_coventions_selected_index = 0;
		const char* calling_coventions[] = { "__cdecl", "__stdcall", "__fastcall"};
		ImGui::Combo("##", &calling_coventions_selected_index, calling_coventions, IM_ARRAYSIZE(calling_coventions));
		ImGui::PopItemWidth();

		ImGui::SameLine();
		static char function_addr_str[32] = "";
		ImGui::InputText("Hex Address", function_addr_str, IM_ARRAYSIZE(function_addr_str));

		ImGui::SameLine();
		ImGui::Text("(");

		static size_t amount_of_parameters = 0;
		for (size_t i = 0; i < amount_of_parameters; i++)
		{
			//ImGui::SameLine();

			//static char str13[32] = ""; // TODO
			//ImGui::InputText("##", str13, IM_ARRAYSIZE(str13));

			if (i < amount_of_parameters - 1)
			{
				ImGui::SameLine();
				ImGui::Text(",");
			}
		}

		ImGui::SameLine();
		if (ImGui::Button("+"))
		{
			amount_of_parameters++;
		}

		ImGui::SameLine();
		ImGui::Text(")");

		for (size_t i = 0; i < hook_manager::inlinehooks.size(); ++i)
		{
			draw_inlinehook(*hook_manager::inlinehooks[i], i);
			ImGui::Separator();
		}

		ImGui::PopID();
	}

	inline void draw_midhook_log(midhook_definition& hook)
	{
		ImGui::SetNextWindowSize(ImVec2(560, 460), ImGuiCond_FirstUseEver);
		if (ImGui::Begin(std::format("0x{:X} History", (uintptr_t)hook.hook.target_address()).c_str(), &hook.show_log_window))
		{
			if (ImGui::Button("Clear Log"))
			{
				hook.clear_log();
			}
			ImGui::SameLine();
			ImGui::Text("%.2f KB", static_cast<double>(hook.get_log().size()) / 1024.0);

			ImGui::Separator();

			if (ImGui::BeginChild("HistoryScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar))
			{
				ImGui::TextUnformatted(hook.get_log().data(), hook.get_log().data() + hook.get_log().size());

				if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
				{
					ImGui::SetScrollHereY(1.0f);
				}
				ImGui::EndChild();
			}
		}

		ImGui::End();
	}

    inline void draw_midhook(midhook_definition& hook, size_t index)
    {
        ImGui::PushID(&hook);

        auto ms_since_hit =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - hook.last_hit_time).count();

        if (ms_since_hit < 1000)
        {
            float t = 1.0f - (float(ms_since_hit) / 1000.0f);

            ImU32 col = ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 1.0f, 0.0f, t * 0.3f));
            ImVec2 p0 = ImGui::GetCursorScreenPos();
            ImVec2 p1 =
            {
                p0.x + ImGui::GetContentRegionAvail().x,
                p0.y + ImGui::GetFrameHeightWithSpacing()
            };

            ImGui::GetWindowDrawList()->AddRectFilled(p0, p1, col);
        }

        ImGui::Text("0x%p", hook.hook.target());

        ImGui::SameLine();

        bool enabled = hook.hook.enabled();
        if (ImGui::Checkbox("Enabled", &enabled))
        {
            enabled ? hook.hook.enable() : hook.hook.disable();
        }

        ImGui::SameLine();

        if (ImGui::Button( hook.show_log_window ? "Close History" : "Open History" ))
        {
            hook.show_log_window = !hook.show_log_window;
        }

		if (hook.show_log_window)
		{
			draw_midhook_log(hook);
		}

        ImGui::PopID();
    }

	void draw_midhook_section()
	{
		ImGui::PushID("midhook");

		ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
		ImGui::TextWrapped("Mid hooks are a very flexible kind of hook that provides access to the CPU context at the point in which the hook was hit. This gives direct register access to nearly any point within a functions execution path.");
		ImGui::PopStyleColor();

		static char add_address_buffer[32] = "";
		ImGui::InputText("Hex Address", add_address_buffer, IM_ARRAYSIZE(add_address_buffer));

		ImGui::SameLine();
		if (ImGui::Button("+"))
		{
			unsigned long long addr = 0;
			try
			{
				addr = std::stoull(add_address_buffer, nullptr, 16);
			}
			catch (...) {}

			if (addr != 0)
			{
				hook_manager::midhooks.push_back(std::make_unique<midhook_definition>(reinterpret_cast<void*>(addr)));

				memset(add_address_buffer, 0, sizeof(add_address_buffer));
			}
		}

		for (size_t i = 0; i < hook_manager::midhooks.size(); ++i)
		{
			ImGui::Separator();
			draw_midhook(*hook_manager::midhooks[i], i);
		}

		ImGui::PopID();
	}

	void draw(reshade::api::effect_runtime* runtime)
	{
		ImGui::PushID("reshade-safetyhook-gui");

		if (ImGui::CollapsingHeader("Mid Hooks", ImGuiTreeNodeFlags_DefaultOpen))
		{
			draw_midhook_section();
		}

		if (ImGui::CollapsingHeader("Inline Hooks", ImGuiTreeNodeFlags_DefaultOpen))
		{
			draw_inlinehook_section();
		}


		ImGui::PopID();
	}
}