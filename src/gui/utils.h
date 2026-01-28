#pragma once
#include <imgui.h>
#include <reshade.hpp>

namespace gui
{
	static inline void flash_row_background(long ms_since_hit, int length_ms = 1000)
	{
        if (ms_since_hit < 1000)
        {
            float t = 1.0f - (float(ms_since_hit) / length_ms);

            ImU32 col = ImGui::ColorConvertFloat4ToU32(ImVec4(0.0f, 1.0f, 0.0f, t * 0.3f));
            ImVec2 p0 = ImGui::GetCursorScreenPos();
            ImVec2 p1 =
            {
                p0.x + ImGui::GetContentRegionAvail().x,
                p0.y + ImGui::GetFrameHeightWithSpacing()
            };

            ImGui::GetWindowDrawList()->AddRectFilled(p0, p1, col);
        }
	}
}