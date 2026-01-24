#pragma once
#include <imgui.h>
#include <reshade.hpp>
#include <string>
#include <vector>
#include "midhook_wrapper.h"

namespace gui
{
	inline void draw_midhook_log(midhook_wrapper& hook)
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

    inline void draw_midhook(midhook_wrapper& hook, size_t index)
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

		if (ImGui::Button("X"))
		{
			midhook_wrapper::midhooks.erase(midhook_wrapper::midhooks.begin() + index);
			ImGui::PopID();
			return;
		}

		ImGui::SameLine();
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

		ImGui::SameLine();
		ImGui::Text("Hits: %d", hook.hit_amount);

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

			std::shared_ptr<midhook_wrapper> midhook = midhook_wrapper::create(reinterpret_cast<void*>(addr));
			if (midhook)
			{
				memset(add_address_buffer, 0, sizeof(add_address_buffer));
			}
			else
			{
				reshade::log::message(reshade::log::level::error, "Failed to create midhook. This address may already be hooked or is invalid.");
			}
		}

		for (size_t i = 0; i < midhook_wrapper::midhooks.size(); ++i)
		{
			ImGui::Separator();
			draw_midhook(*midhook_wrapper::midhooks[i], i);
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

		ImGui::PopID();
	}
}