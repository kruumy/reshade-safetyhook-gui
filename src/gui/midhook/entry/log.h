#pragma once

namespace gui::midhook::entry::log
{
	inline void draw(midhook_wrapper& hook)
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

}

