#pragma once

#include <optional>
#include <string>

#include "common.h"

namespace cdqt {

std::optional<BinaryType> detectBinaryType(const fs::path& p, std::string& whyNot);

} // namespace cdqt


