#include "deploy.h"

#include <algorithm>
#include <iostream>

#include "fs_ops.h"
#include "macho_fixups.h"
#include "pe_patch.h"
#include "qml.h"
#include "qt_paths.h"
#include "resolve.h"
#include "stage.h"
#include "translations.h"
#include "util.h"

namespace cdqt {

static void printResolved(const std::vector<fs::path>& libs) {
    if (libs.empty()) return;
    std::cout << "Resolved shared libraries (filtered):\n";
    for (const auto& p : libs) std::cout << "  " << p << "\n";
}

static void deployPE(const DeployPlan& plan) {
    auto libs = resolveAndRecurse(plan);
    printResolved(libs);
    copyResolvedForPE(plan, libs);
    copyMainPE(plan);
    applyOverlays(plan);

    for (const auto& p : libs) {
        std::string base = p.filename().string();
        std::string lower = base;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        if (lower == "qt6core.dll") {
            fs::path staged = plan.outputRoot / p.filename();
            std::error_code ec;
            if (fs::exists(staged, ec)) {
                if (isVerbose()) std::cout << "[pe] patch Qt6Core.dll: " << staged << "\n";
                patchQtCoreDllPrefixInfixPE(staged);
            }
            break;
        }
    }

    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);
    copyPluginsPE(ctx, plan, libs);
    copyQmlModules(ctx, plan);
    deployTranslations(ctx, plan);
    resolveQmlPluginDependencies(plan);
}

static void deployELF(const DeployPlan& plan) {
    auto libs = resolveAndRecurse(plan);
    printResolved(libs);
    copyResolvedForELF(plan, libs);
    copyMainAndPatchELF(plan);

    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);
    copyPluginsELF(ctx, plan);
    copyQmlModules(ctx, plan);
    deployTranslations(ctx, plan);
    applyOverlays(plan);
    copyPluginsELF(ctx, plan);
    resolveQmlPluginDependencies(plan);
}

static void deployMachO(const DeployPlan& plan) {
    auto libs = resolveAndRecurse(plan);
    printResolved(libs);
    copyResolvedForMachO(plan, libs);
    copyMainAndPatchMachO(plan);

    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);
    copyPluginsMachO(ctx, plan);
    copyQmlModules(ctx, plan);
    deployTranslations(ctx, plan);
    applyOverlays(plan);
    resolveQmlPluginDependencies(plan);
    fixInstallNamesMachO(plan);
}

void deploy(const DeployPlan& plan) {
    ensureOutputLayout(plan);
    switch (plan.type) {
        case BinaryType::PE: deployPE(plan); break;
        case BinaryType::ELF: deployELF(plan); break;
        case BinaryType::MACHO: deployMachO(plan); break;
    }
}

} // namespace cdqt


