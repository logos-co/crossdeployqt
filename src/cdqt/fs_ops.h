#pragma once

#include <filesystem>

#include "common.h"

namespace cdqt {

namespace fs = std::filesystem;

void ensureOutputLayout(const DeployPlan& plan);

bool copyFileOverwrite(const fs::path& from, const fs::path& to);

void mergeDirectoryTree(const fs::path& srcRoot, const fs::path& dstRoot);
void applyOverlays(const DeployPlan& plan);

void writeQtConfIfNeeded(const DeployPlan& plan);

} // namespace cdqt


