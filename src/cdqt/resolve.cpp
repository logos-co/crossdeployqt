#include "resolve.h"

#include <iostream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <unordered_map>

#include "deps_parse.h"
#include "util.h"

namespace cdqt {

static void addSearchDirInternal(ResolveContext& ctx, const fs::path& dir) {
    if (dir.empty()) return;
    std::error_code ec;
    fs::path can = fs::weakly_canonical(dir, ec);
    const std::string key = (ec ? dir : can).string();
    if (ctx.searchDirSet.insert(key).second) {
        ctx.searchDirs.emplace_back(key);
    }
}

void addSearchDir(ResolveContext& ctx, const fs::path& dir) {
    addSearchDirInternal(ctx, dir);
}

void ensureEnvForResolution(ResolveContext& ctx) {
    addSearchDirInternal(ctx, ctx.plan.binaryPath.parent_path());

    const auto qtLibs = ctx.qt.qtInstallLibs;
    const auto qtBins = ctx.qt.qtInstallBins;

    if (ctx.plan.type == BinaryType::ELF) {
        std::string ld = getEnv("LD_LIBRARY_PATH");
        for (const auto& p : splitPaths(ld, pathListSep())) if (!p.empty()) addSearchDirInternal(ctx, p);
        if (!qtLibs.empty()) addSearchDirInternal(ctx, qtLibs);
        if (!qtLibs.empty()) {
            std::string newLd = qtLibs.string();
            if (!ld.empty()) newLd += std::string(1, pathListSep()) + ld;
            setEnv("LD_LIBRARY_PATH", newLd);
        }
    } else if (ctx.plan.type == BinaryType::PE) {
        std::string path = getEnv("PATH");
        std::vector<std::string> pv = splitPaths(path, pathListSep());
        for (const auto& p : pv) if (!p.empty()) addSearchDirInternal(ctx, p);
        if (!qtBins.empty()) addSearchDirInternal(ctx, qtBins);
        if (!qtBins.empty()) {
            std::string newPath = qtBins.string();
            if (!path.empty()) newPath += std::string(1, pathListSep()) + path;
            setEnv("PATH", newPath);
        }
        for (const auto& p : pv) {
            if (p.size() > 4 && p.rfind("/bin", p.size() - 4) != std::string::npos) {
                fs::path base = fs::path(p).parent_path();
                std::error_code ec2;
                fs::path q1 = base / "qml";
                if (fs::exists(q1, ec2)) ctx.qmlImportPaths.push_back(q1);
                ec2.clear();
                fs::path q2 = base / "lib" / "qt-6" / "qml";
                if (fs::exists(q2, ec2)) ctx.qmlImportPaths.push_back(q2);
            }
        }
    } else {
        std::string dyld = getEnv("DYLD_LIBRARY_PATH");
        for (const auto& p : splitPaths(dyld, pathListSep())) if (!p.empty()) addSearchDirInternal(ctx, p);
        std::string dyldfw = getEnv("DYLD_FRAMEWORK_PATH");
        for (const auto& p : splitPaths(dyldfw, pathListSep())) if (!p.empty()) addSearchDirInternal(ctx, p);
        if (!qtLibs.empty()) addSearchDirInternal(ctx, qtLibs);
        if (!qtLibs.empty()) {
            std::string newDyld = qtLibs.string();
            if (!dyld.empty()) newDyld += std::string(1, pathListSep()) + dyld;
            setEnv("DYLD_LIBRARY_PATH", newDyld);
            std::string newDyldFw = qtLibs.string();
            if (!dyldfw.empty()) newDyldFw += std::string(1, pathListSep()) + dyldfw;
            setEnv("DYLD_FRAMEWORK_PATH", newDyldFw);
        }
    }

    if (!ctx.qt.qtInstallQml.empty()) {
        std::error_code ec;
        if (fs::exists(ctx.qt.qtInstallQml, ec)) ctx.qmlImportPaths.push_back(ctx.qt.qtInstallQml);
    }
    std::string qml2Env = getEnv("QML2_IMPORT_PATH");
    for (const auto& p : splitPaths(qml2Env, pathListSep())) {
        if (p.empty()) continue;
        std::error_code ec;
        if (fs::exists(p, ec)) ctx.qmlImportPaths.emplace_back(p);
    }
    for (const auto& r : ctx.plan.qmlRoots) ctx.cliQmlRoots.push_back(r);
    std::string envRoots = getEnv("QML_ROOT");
    for (const auto& p : splitPaths(envRoots, pathListSep())) if (!p.empty()) ctx.cliQmlRoots.emplace_back(p);
}

static std::string expandElfOrigin(std::string p, const fs::path& subject) {
    const std::string base = subject.parent_path().string();
    auto sub = [&](const char* pat){
        size_t pos = 0;
        const size_t n = std::strlen(pat);
        while ((pos = p.find(pat, pos)) != std::string::npos) {
            p.replace(pos, n, base);
            pos += base.size();
        }
    };
    sub("${ORIGIN}");
    sub("$ORIGIN");
    return p;
}

static fs::path expandMachOToken(const std::string& p, const fs::path& subjectBin, const fs::path& mainExe) {
    fs::path dir = subjectBin.parent_path();
    if (p.rfind("@loader_path/", 0) == 0)        return fs::weakly_canonical(dir / p.substr(13));
    if (p.rfind("@executable_path/", 0) == 0)    return fs::weakly_canonical(mainExe.parent_path() / p.substr(17));
    return fs::path(p);
}

std::optional<fs::path> findLibrary(const std::string& nameOrPath, const ResolveContext& ctx) {
    fs::path p(nameOrPath);
    std::error_code ec;
    if (p.is_absolute() && fs::exists(p, ec)) return fs::weakly_canonical(p, ec);
    for (const auto& dir : ctx.searchDirs) {
        fs::path cand = dir / nameOrPath;
        std::error_code ec2;
        if (fs::exists(cand, ec2)) return fs::weakly_canonical(cand, ec2);
    }
    return std::nullopt;
}

static std::optional<fs::path> resolveELFRef(const std::string& ref,
                                             const fs::path& subject,
                                             const std::vector<std::string>& subjectRpaths,
                                             const ResolveContext& ctx) {
    std::error_code ec;
    fs::path p(ref);
    if (p.is_absolute() && fs::exists(p, ec)) return fs::weakly_canonical(p, ec);
    for (const auto& rp : subjectRpaths) {
        fs::path base = expandElfOrigin(rp, subject);
        fs::path cand = base / ref;
        std::error_code ec2;
        if (fs::exists(cand, ec2)) return fs::weakly_canonical(cand, ec2);
    }
    return findLibrary(ref, ctx);
}

static std::optional<fs::path> resolveMachORef(const std::string& ref,
                                               const fs::path& subject,
                                               const std::vector<std::string>& subjectRpaths,
                                               const ResolveContext& ctx,
                                               const fs::path& mainExe) {
    std::error_code ec;
    fs::path p(ref);
    if (p.is_absolute() && fs::exists(p, ec)) return fs::weakly_canonical(p, ec);
    if (ref.rfind("@loader_path/", 0) == 0 || ref.rfind("@executable_path/", 0) == 0) {
        fs::path cand = expandMachOToken(ref, subject, mainExe);
        if (fs::exists(cand, ec)) return fs::weakly_canonical(cand, ec);
    }
    if (ref.rfind("@rpath/", 0) == 0) {
        const std::string tail = ref.substr(7);
        for (const auto& rp : subjectRpaths) {
            fs::path base = expandMachOToken(rp, subject, mainExe);
            fs::path cand = base / tail;
            std::error_code ec2;
            if (fs::exists(cand, ec2)) return fs::weakly_canonical(cand, ec2);
        }
    }
    return findLibrary(ref, ctx);
}

std::optional<fs::path> resolveRef(BinaryType type,
                                   const std::string& ref,
                                   const fs::path& subject,
                                   const ParseResult& subjectParsed,
                                   const ResolveContext& ctx,
                                   ParseCache& cache,
                                   const fs::path& mainExe) {
    if (type == BinaryType::ELF) {
        return resolveELFRef(ref, subject, subjectParsed.rpaths, ctx);
    }
    if (type == BinaryType::PE) {
        return findLibrary(ref, ctx);
    }
    const auto& rps = machoRpathsFor(subject, cache);
    return resolveMachORef(ref, subject, rps, ctx, mainExe);
}

bool isQtLibraryName(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    return lower.find("qt6") != std::string::npos || lower.rfind("qt", 0) == 0;
}

bool shouldDeployLibrary(const fs::path& libPath, const std::string&, BinaryType type, const ResolveContext& ctx) {
    const fs::path dir = libPath.has_parent_path() ? libPath.parent_path() : fs::path();
    const std::string base = libPath.filename().string();
    auto inQtPath = [&]() -> bool {
        if (!ctx.qt.qtInstallLibs.empty() && libPath.string().find(ctx.qt.qtInstallLibs.string()) == 0) return true;
        if (!ctx.qt.qtInstallBins.empty() && libPath.string().find(ctx.qt.qtInstallBins.string()) == 0) return true;
        if (!ctx.qt.qtInstallPrefix.empty() && libPath.string().find(ctx.qt.qtInstallPrefix.string()) == 0) return true;
        return false;
    };

    if (type == BinaryType::ELF) {
        if (libPath.string().rfind("/lib", 0) == 0 || libPath.string().rfind("/usr/lib", 0) == 0) {
            return isQtLibraryName(base) || inQtPath();
        }
        return isQtLibraryName(base) || inQtPath() || dir == ctx.plan.binaryPath.parent_path();
    } else if (type == BinaryType::PE) {
        std::string lower = base;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        static const char* systemPrefixes[] = {"api-ms-win-", "ext-ms-win-"};
        for (auto p : systemPrefixes) { if (lower.rfind(p, 0) == 0) return false; }
        static const std::unordered_set<std::string> systemDlls = {
            "kernel32.dll","user32.dll","gdi32.dll","shell32.dll","ole32.dll","advapi32.dll","ws2_32.dll",
            "ntdll.dll","sechost.dll","shlwapi.dll","comdlg32.dll","imm32.dll","version.dll","winmm.dll","cfgmgr32.dll"
        };
        if (systemDlls.count(lower)) return false;
        const bool inNixStore = libPath.string().rfind("/nix/store/", 0) == 0;
        return inNixStore || isQtLibraryName(base) || inQtPath() || dir == ctx.plan.binaryPath.parent_path();
    } else {
        std::string s = libPath.string();
        if (s.rfind("/System/Library/Frameworks/", 0) == 0 || s.rfind("/usr/lib/", 0) == 0) return false;
        return isQtLibraryName(base) || inQtPath() || dir == ctx.plan.binaryPath.parent_path();
    }
}

std::vector<fs::path> resolveAndRecurse(const DeployPlan& plan) {
    ResolveContext ctx{plan, queryQtPaths(), {}, {}, {}, {}};
    ensureEnvForResolution(ctx);

    ParseCache cache;
    const ParseResult& pr = parseDepsCached(plan.binaryPath, plan.type, cache);

    std::vector<fs::path> stack;
    for (const auto& dep : pr.dependencies) {
        std::optional<fs::path> found = resolveRef(plan.type, dep, plan.binaryPath, pr, ctx, cache, plan.binaryPath);
        if (found) {
            if (shouldDeployLibrary(*found, dep, plan.type, ctx)) stack.push_back(*found);
        } else if (isQtLibraryName(dep)) {
            throw std::runtime_error("Required Qt library not found in search paths: " + dep);
        }
    }

    std::unordered_set<std::string> visited;
    while (!stack.empty()) {
        fs::path cur = stack.back();
        stack.pop_back();
        if (isVerbose()) std::cout << "[resolve] Inspect: " << cur << "\n";
        std::error_code ec;
        fs::path canon = fs::weakly_canonical(cur, ec);
        std::string key = ec ? cur.string() : canon.string();
        if (visited.count(key)) continue;
        visited.insert(key);

        const ParseResult& prChild = parseDepsCached(cur, plan.type, cache);
        for (const auto& dep : prChild.dependencies) {
            if (isVerbose()) std::cout << "[resolve]   dep: " << dep << "\n";
            std::optional<fs::path> found = resolveRef(plan.type, dep, cur, prChild, ctx, cache, plan.binaryPath);
            if (found) {
                if (shouldDeployLibrary(*found, dep, plan.type, ctx)) {
                    if (isVerbose()) std::cout << "[resolve]     push: " << *found << "\n";
                    stack.push_back(*found);
                }
            } else {
                if (isQtLibraryName(dep)) {
                    throw std::runtime_error("Required Qt library not found in search paths: " + dep);
                }
            }
        }
    }

    std::vector<fs::path> libs;
    libs.reserve(visited.size());
    for (const auto& k : visited) {
        if (k == plan.binaryPath.string()) continue;
        libs.emplace_back(k);
    }
    return libs;
}

} // namespace cdqt


