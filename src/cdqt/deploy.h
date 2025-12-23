#pragma once

#include "common.h"

namespace cdqt {

// High-level deploy entrypoint: resolves + stages libraries/plugins/qml/translations for plan.type.
void deploy(const DeployPlan& plan);

} // namespace cdqt


