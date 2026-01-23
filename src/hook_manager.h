#pragma once
#include "midhook_wrapper.h"
#include <vector>
#include <memory>

namespace hook_manager
{
	inline std::vector<std::unique_ptr<midhook_wrapper>> midhooks;
}
