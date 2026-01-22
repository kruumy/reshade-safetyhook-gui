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

	void draw_midhook_history(midhook_definition& hook)
	{
		if (ImGui::Begin(std::format("0x{:X} History", (uintptr_t)hook.hook.target()).c_str(), &hook.show_history))
		{
			ImGui::BeginChild("HistoryScrollRegion");
			for (auto& item : hook.get_context_history())
			{
				ImGui::Text("eax: 0x%X", item.eax);
				ImGui::Text("ebp: 0x%X", item.ebp);
				ImGui::Text("ecx: 0x%X", item.ecx);
				ImGui::Separator();
			}
			ImGui::EndChild();
		}
		ImGui::End();
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
			hook_manager::midhooks.erase(hook_manager::midhooks.begin() + index);
			ImGui::PopID();
			return;
		}

		ImGui::SameLine();

		ImGui::Text("0x%p", hook.hook.target());

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

		ImGui::SameLine();
		if (ImGui::Button(hook.show_history ? "Close History" : "Open History"))
		{
			hook.show_history = !hook.show_history;
		}

		if (hook.show_history)
		{
			draw_midhook_history(hook);
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
			draw_midhook(*hook_manager::midhooks[i], i);
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