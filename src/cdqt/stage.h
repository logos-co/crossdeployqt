#pragma once

#include <filesystem>
#include <vector>

#include "common.h"
#include "resolve.h"

namespace cdqt {

namespace fs = std::filesystem;

void copyResolvedForPE(const DeployPlan& plan, const std::vector<fs::path>& libs);
void copyResolvedForELF(const DeployPlan& plan, const std::vector<fs::path>& libs);
void copyResolvedForMachO(const DeployPlan& plan, const std::vector<fs::path>& libs);

void copyPluginsPE(const ResolveContext& ctx, const DeployPlan& plan, const std::vector<fs::path>& resolvedLibs);
void copyPluginsELF(const ResolveContext& ctx, const DeployPlan& plan);
void copyPluginsMachO(const ResolveContext& ctx, const DeployPlan& plan);

void copyMainPE(const DeployPlan& plan);
void copyMainAndPatchELF(const DeployPlan& plan);
void copyMainAndPatchMachO(const DeployPlan& plan);

} // namespace cdqt


