#pragma once

#include <optional>
#include <set>
#include <unordered_set>
#include <vector>

#include "common.h"
#include "qt_paths.h"

namespace cdqt {

struct ParseResult;
struct ParseCache;

struct ResolveContext {
    DeployPlan plan;
    QtPathsInfo qt;
    std::vector<fs::path> searchDirs;        // directories used to resolve deps
    std::vector<fs::path> qmlImportPaths;    // directories for QML imports
    std::vector<fs::path> cliQmlRoots;       // from --qml-root and env
    std::unordered_set<std::string> searchDirSet; // for dedup
};

void addSearchDir(ResolveContext& ctx, const fs::path& dir);
void ensureEnvForResolution(ResolveContext& ctx);

std::optional<fs::path> findLibrary(const std::string& nameOrPath, const ResolveContext& ctx);

bool isQtLibraryName(const std::string& name);
bool shouldDeployLibrary(const fs::path& libPath, const std::string& sonameOrDll, BinaryType type, const ResolveContext& ctx);

// Resolve one dependency reference (e.g. "libFoo.so.1", "/abs/path", "@rpath/QtCore.framework/..."),
// using platform rules + rpaths from parsed metadata.
std::optional<fs::path> resolveRef(BinaryType type,
                                   const std::string& ref,
                                   const fs::path& subject,
                                   const ParseResult& subjectParsed,
                                   const ResolveContext& ctx,
                                   ParseCache& cache,
                                   const fs::path& mainExe);

std::vector<fs::path> resolveAndRecurse(const DeployPlan& plan);

} // namespace cdqt


