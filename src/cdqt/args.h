#pragma once

#include <optional>

#include "common.h"

namespace cdqt {

void printUsage(const char* argv0);
std::optional<Args> parseArgs(int argc, char** argv);

} // namespace cdqt


