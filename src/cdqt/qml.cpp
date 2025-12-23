#include "qml.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <unordered_set>

#include "deps_parse.h"
#include "fs_ops.h"
#include "qt_paths.h"
#include "resolve.h"
#include "stage.h"
#include "util.h"

namespace cdqt {

struct QmlModuleEntry {
    fs::path sourcePath;
    std::string relativePath;
};

static std::vector<fs::path> discoverQmlRoots(const ResolveContext& ctx) {
    std::vector<fs::path> roots;
    for (const auto& r : ctx.cliQmlRoots) roots.push_back(r);
    std::string envRoot = getEnv("QML_ROOT");
    if (!envRoot.empty()) roots.emplace_back(envRoot);

    std::error_code ec;
    fs::path cwd = fs::current_path(ec);
    auto hasQml = [](const fs::path& d) -> bool {
        std::error_code e;
        if (!fs::exists(d, e) || !fs::is_directory(d, e)) return false;
        for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, e);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(e) && it->path().extension() == ".qml") return true;
        }
        return false;
    };

    if (envRoot.empty() && ctx.cliQmlRoots.empty()) {
        if (!cwd.empty() && hasQml(cwd)) roots.push_back(cwd);
        fs::path binDir = ctx.plan.binaryPath.parent_path();
        if (!binDir.empty() && hasQml(binDir)) roots.push_back(binDir);
    }

    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    return roots;
}

static std::vector<QmlModuleEntry> runQmlImportScanner(const ResolveContext& ctx, const std::vector<fs::path>& roots) {
    std::vector<QmlModuleEntry> result;
    if (roots.empty()) return result;

    std::string importArgs;
    for (const auto& p : ctx.qmlImportPaths) {
        importArgs += " -importPath " + shellEscape(p.string());
    }

    for (const auto& root : roots) {
        int code = 0;
        std::string cmd = std::string("qmlimportscanner -rootPath ") + shellEscape(root.string()) + importArgs;
        std::string out = runCommand(cmd, code);
        if (code != 0 || out.empty()) continue;

        std::istringstream iss(out);
        std::string line;
        QmlModuleEntry current;
        bool inObject = false;
        while (std::getline(iss, line)) {
            if (line.find('{') != std::string::npos) { inObject = true; current = QmlModuleEntry(); }
            if (inObject) {
                auto ppos = line.find("\"path\"");
                if (ppos != std::string::npos) {
                    auto q1 = line.find('"', ppos + 6);
                    auto q2 = q1 == std::string::npos ? std::string::npos : line.find('"', q1 + 1);
                    if (q1 != std::string::npos && q2 != std::string::npos) {
                        current.sourcePath = fs::path(line.substr(q1 + 1, q2 - q1 - 1));
                    }
                }
                auto rpos = line.find("\"relativePath\"");
                if (rpos != std::string::npos) {
                    auto q1 = line.find('"', rpos + 14);
                    auto q2 = q1 == std::string::npos ? std::string::npos : line.find('"', q1 + 1);
                    if (q1 != std::string::npos && q2 != std::string::npos) {
                        current.relativePath = line.substr(q1 + 1, q2 - q1 - 1);
                    }
                }
            }
            if (line.find('}') != std::string::npos && inObject) {
                inObject = false;
                if (!current.sourcePath.empty()) {
                    if (current.relativePath.empty()) {
                        std::string sp = current.sourcePath.string();
                        std::string qp = ctx.qt.qtInstallQml.string();
                        if (!qp.empty() && sp.rfind(qp, 0) == 0) {
                            std::string rel = sp.substr(qp.size());
                            if (!rel.empty() && (rel[0] == '/' || rel[0] == '\\')) rel.erase(0, 1);
                            current.relativePath = rel;
                        } else {
                            current.relativePath = current.sourcePath.filename().string();
                        }
                    }
                    result.push_back(current);
                }
            }
        }
    }

    std::sort(result.begin(), result.end(), [](const QmlModuleEntry& a, const QmlModuleEntry& b){ return a.sourcePath < b.sourcePath; });
    result.erase(std::unique(result.begin(), result.end(), [](const QmlModuleEntry& a, const QmlModuleEntry& b){ return a.sourcePath == b.sourcePath; }), result.end());
    return result;
}

void copyQmlModules(const ResolveContext& ctx, const DeployPlan& plan) {
    auto roots = discoverQmlRoots(ctx);
    if (roots.empty()) return;
    if (isVerbose()) {
        std::cout << "[qml] roots:";
        for (auto& r : roots) std::cout << " " << r;
        std::cout << "\n";
    }

    auto modules = runQmlImportScanner(ctx, roots);
    if (modules.empty()) return;

    std::error_code ec;
    fs::path qmlDestBase = plan.type == BinaryType::MACHO
        ? plan.outputRoot / "Contents" / "Resources" / "qml"
        : (plan.type == BinaryType::ELF ? plan.outputRoot / "usr" / "qml" : plan.outputRoot / "qml");

    for (const auto& m : modules) {
        if (isVerbose()) std::cout << "[qml] module: " << m.sourcePath << " -> " << (qmlDestBase / m.relativePath) << "\n";
        fs::path dst = qmlDestBase / m.relativePath;
        fs::create_directories(dst, ec);
        ec.clear();
        try {
            for (auto it = fs::recursive_directory_iterator(m.sourcePath, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it->is_directory(ec)) continue;

                fs::path src = it->path();
                fs::path rel = fs::relative(src, m.sourcePath, ec);
                fs::path out = dst / rel;

                if (plan.type == BinaryType::MACHO) {
                    std::error_code isSymlinkEc;
                    const bool isLink = it->is_symlink(isSymlinkEc);
                    fs::path target = src;
                    if (isLink) {
                        std::error_code le;
                        fs::path linkTarget = fs::read_symlink(src, le);
                        if (!le) {
                            std::error_code wc;
                            fs::path absTarget = fs::weakly_canonical(src.parent_path() / linkTarget, wc);
                            if (!wc) target = absTarget;
                        }
                    }
                    if (target.extension() == ".dylib") {
                        fs::path quickDir = plan.outputRoot / "Contents" / "PlugIns" / "quick";
                        fs::create_directories(quickDir, ec);
                        fs::path moved = quickDir / target.filename();
                        if (isVerbose()) std::cout << "[qml] stage dylib: " << target << " -> " << moved << "\n";
                        if (!copyFileOverwrite(target, moved)) {
                            throw std::runtime_error(std::string("Failed to copy QML plugin dylib: ") + target.string());
                        }
                        std::error_code mkEc;
                        fs::create_directories(out.parent_path(), mkEc);
                        std::error_code rmEc;
                        fs::remove(out, rmEc);
                        try {
                            fs::create_symlink(fs::relative(moved, out.parent_path()), out);
                        } catch (...) {
                            copyFileOverwrite(moved, out);
                        }
                        continue;
                    }
                    if (isLink) continue;
                } else {
                    std::error_code isLinkEc2;
                    if (it->is_symlink(isLinkEc2)) continue;
                }

                if (!copyFileOverwrite(src, out)) {
                    throw std::runtime_error(std::string("Failed to copy QML file: ") + src.string());
                }
            }
        } catch (...) {
            std::cerr << "Warning: failed to traverse QML module: " << m.sourcePath << "\n";
        }
    }
}

static std::vector<fs::path> listQmlPluginLibraries(const DeployPlan& plan) {
    std::vector<fs::path> libs;
    std::error_code ec;
    fs::path qmlBase = plan.type == BinaryType::MACHO
        ? plan.outputRoot / "Contents" / "Resources" / "qml"
        : (plan.type == BinaryType::ELF ? plan.outputRoot / "usr" / "qml" : plan.outputRoot / "qml");
    if (!fs::exists(qmlBase, ec)) return libs;
    std::string ext = plan.type == BinaryType::PE ? ".dll" : (plan.type == BinaryType::ELF ? ".so" : ".dylib");
    std::unordered_set<std::string> seen;
    for (auto it = fs::recursive_directory_iterator(qmlBase, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); ++it) {
        if (!it->is_regular_file(ec)) continue;
        if (it->path().extension() == ext) {
            std::string key = fs::weakly_canonical(it->path(), ec).string();
            if (!seen.count(key)) { seen.insert(key); libs.push_back(it->path()); }
        }
    }
    if (plan.type == BinaryType::MACHO) {
        fs::path quick = plan.outputRoot / "Contents" / "PlugIns" / "quick";
        if (fs::exists(quick, ec)) {
            for (auto it = fs::recursive_directory_iterator(quick, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it->is_regular_file(ec) && it->path().extension() == ".dylib") {
                    std::string key = fs::weakly_canonical(it->path(), ec).string();
                    if (!seen.count(key)) { seen.insert(key); libs.push_back(it->path()); }
                }
            }
        }
    }
    return libs;
}

void resolveQmlPluginDependencies(const DeployPlan& plan) {
    auto qmlLibs = listQmlPluginLibraries(plan);
    if (qmlLibs.empty()) return;

    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);

    std::vector<fs::path> stack;
    for (const auto& lib : qmlLibs) {
        if (isVerbose()) std::cout << "[qml-deps] seed: " << lib << "\n";
        stack.push_back(lib);
    }

    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> result;
    ParseCache cache;

    while (!stack.empty()) {
        fs::path cur = stack.back();
        stack.pop_back();
        std::error_code ec;
        fs::path canon = fs::weakly_canonical(cur, ec);
        std::string key = ec ? cur.string() : canon.string();
        if (visited.count(key)) continue;
        visited.insert(key);

        const ParseResult& prChild = parseDepsCached(cur, plan.type, cache);
        for (const auto& dep : prChild.dependencies) {
            if (isVerbose()) std::cout << "[qml-deps]   dep: " << dep << "\n";
            std::optional<fs::path> found = resolveRef(plan.type, dep, cur, prChild, ctx, cache, plan.binaryPath);
            if (found) {
                if (shouldDeployLibrary(*found, dep, plan.type, ctx)) {
                    std::string fkey = fs::weakly_canonical(*found, ec).string();
                    if (isVerbose()) std::cout << "[qml-deps]     push: " << *found << "\n";
                    if (!visited.count(fkey)) stack.push_back(*found);
                    result.insert(fkey);
                }
            }
        }
    }

    std::vector<fs::path> uniqueDeps;
    for (const auto& k : result) uniqueDeps.emplace_back(k);
    if (uniqueDeps.empty()) return;

    if (plan.type == BinaryType::PE) copyResolvedForPE(plan, uniqueDeps);
    else if (plan.type == BinaryType::ELF) copyResolvedForELF(plan, uniqueDeps);
    else copyResolvedForMachO(plan, uniqueDeps);
}

} // namespace cdqt


