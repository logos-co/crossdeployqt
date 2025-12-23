#pragma once

#include "common.h"
#include "resolve.h"

namespace cdqt {

void copyQmlModules(const ResolveContext& ctx, const DeployPlan& plan);
void resolveQmlPluginDependencies(const DeployPlan& plan);

} // namespace cdqt


