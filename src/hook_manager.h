#pragma once
#include "midhook_definition.h"
#include "inlinehook_definition.h"
#include <vector>
#include <memory>

namespace hook_manager
{
	inline std::vector<std::unique_ptr<midhook_definition>> midhooks;
	inline std::vector<std::unique_ptr<inlinehook_definition>> inlinehooks;
}
