#pragma once
#include <imgui.h>
#include <reshade.hpp>
#include "hook_manager.h"
#include <string>

namespace gui
{
	void draw_inlinehook_section()
	{
		ImGui::PushID("inlinehook");

		ImGui::PopID();
	}

	void draw_midhook(midhook_definition& hook, size_t index)
	{
		ImGui::PushID(&hook);

		auto ms_since_hit = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - hook.last_hit_time).count();
		if (ms_since_hit < 1000)
		{
			float intensity = 1.0f - (static_cast<float>(ms_since_hit) / 1000.0f);
			ImU32 fade_color = ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 1.0f, 0.0f, intensity * 0.3f));
			ImVec2 p_min = ImGui::GetCursorScreenPos();
			ImVec2 p_max = ImVec2(p_min.x + ImGui::GetContentRegionAvail().x, p_min.y + ImGui::GetFrameHeightWithSpacing());
			ImGui::GetWindowDrawList()->AddRectFilled(p_min, p_max, fade_color);
		}

		if (ImGui::Button("X"))
		{
			hook_manager::hooks.erase(hook_manager::hooks.begin() + index);
			ImGui::PopID();
			return;
		}

		ImGui::SameLine();

		char address_text[32];
		sprintf_s(address_text, "0x%p", hook.hook.target());
		ImGui::Text("%s", address_text);

		ImGui::SameLine();

		bool is_enabled = hook.hook.enabled();
		if (ImGui::Checkbox("Enabled", &is_enabled))
		{
			if (is_enabled)
			{
				hook.hook.enable();
			}
			else
			{
				hook.hook.disable();
			}
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
		ImGui::InputText("Hex Address", add_address_buffer, sizeof(add_address_buffer));

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
				hook_manager::hooks.push_back(std::make_unique<midhook_definition>(reinterpret_cast<void*>(addr)));

				memset(add_address_buffer, 0, sizeof(add_address_buffer));
			}
		}

		for (size_t i = 0; i < hook_manager::hooks.size(); ++i)
		{
			draw_midhook(*hook_manager::hooks[i], i);
			ImGui::Separator();
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

		ImGui::Separator();

		if (ImGui::CollapsingHeader("Inline Hooks", ImGuiTreeNodeFlags_DefaultOpen))
		{
			draw_inlinehook_section();
		}


		ImGui::PopID();
	}
}