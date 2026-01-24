#pragma once=
#include "imgui.h"
#include "entry/entry.h"

namespace gui::midhook
{
	void draw()
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
			entry::draw(*midhook_wrapper::midhooks[i], i);
		}

		ImGui::PopID();
	}

}
