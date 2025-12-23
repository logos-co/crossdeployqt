#include "stage.h"

#include <algorithm>
#include <iostream>
#include <unordered_set>

#include "deps_parse.h"
#include "fs_ops.h"
#include "qt_paths.h"
#include "util.h"

namespace cdqt {

void copyResolvedForPE(const DeployPlan& plan, const std::vector<fs::path>& libs) {
    for (const auto& lib : libs) {
        fs::path dest = plan.outputRoot / lib.filename();
        if (!copyFileOverwrite(lib, dest)) {
            std::cerr << "Warning: failed to copy " << lib << " -> " << dest << "\n";
        }
    }
    writeQtConfIfNeeded(plan);
}

void copyPluginsPE(const ResolveContext& ctx, const DeployPlan& plan, const std::vector<fs::path>& resolvedLibs) {
    std::vector<fs::path> pluginRoots;
    if (!ctx.qt.qtInstallPlugins.empty()) pluginRoots.push_back(ctx.qt.qtInstallPlugins);

    std::string mingwPlugins = getEnv("MINGW_QT_PLUGINS");
    for (const auto& p : splitPaths(mingwPlugins, pathListSep())) if (!p.empty()) pluginRoots.emplace_back(p);

    std::string path = getEnv("PATH");
    for (const auto& p : splitPaths(path, pathListSep())) {
        if (p.size() > 4 && p.rfind("/bin", p.size() - 4) != std::string::npos) {
            fs::path base = fs::path(p).parent_path();
            std::error_code ec;
            fs::path root1 = base / "plugins";
            if (fs::exists(root1, ec)) pluginRoots.push_back(root1);
            ec.clear();
            fs::path root2 = base / "lib" / "qt-6" / "plugins";
            if (fs::exists(root2, ec)) pluginRoots.push_back(root2);
        }
    }

    for (const auto& lib : resolvedLibs) {
        std::string base = lib.filename().string();
        std::string lower = base;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
        if (lower == "qt6core.dll") {
            fs::path binDir = lib.parent_path();
            std::error_code ec;
            fs::path root1 = binDir.parent_path() / "plugins";
            if (fs::exists(root1, ec)) pluginRoots.push_back(root1);
            ec.clear();
            fs::path root2 = binDir.parent_path() / "lib" / "qt-6" / "plugins";
            if (fs::exists(root2, ec)) pluginRoots.push_back(root2);
        }
    }

    std::sort(pluginRoots.begin(), pluginRoots.end());
    pluginRoots.erase(std::unique(pluginRoots.begin(), pluginRoots.end()), pluginRoots.end());

    for (const auto& src : pluginRoots) {
        fs::path platformDll = src / "platforms" / "qwindows.dll";
        if (!fs::exists(platformDll)) continue;
        copyFileOverwrite(platformDll, plan.outputRoot / "plugins" / "platforms" / platformDll.filename());
        for (const char* name : {"qjpeg.dll","qico.dll","qgif.dll","qpng.dll"}) {
            fs::path p = src / "imageformats" / name;
            if (fs::exists(p)) copyFileOverwrite(p, plan.outputRoot / "plugins" / "imageformats" / p.filename());
        }
        break;
    }
}

void copyResolvedForELF(const DeployPlan& plan, const std::vector<fs::path>& libs) {
    fs::path libDir = plan.outputRoot / "usr" / "lib";
    std::error_code ec;
    fs::create_directories(libDir, ec);
    for (const auto& lib : libs) {
        fs::path dest = libDir / lib.filename();
        if (!copyFileOverwrite(lib, dest)) {
            std::cerr << "Warning: failed to copy " << lib << " -> " << dest << "\n";
            continue;
        }
        std::error_code ecPerm;
        fs::permissions(dest, fs::perms::owner_write, fs::perm_options::add, ecPerm);
        auto soname = queryElfSoname(dest);
        if (soname) {
            const std::string destName = dest.filename().string();
            if (*soname != destName) {
                fs::path linkPath = libDir / *soname;
                std::error_code sec;
                if (fs::exists(linkPath)) fs::remove(linkPath, sec);
                sec.clear();
                try {
                    fs::create_symlink(dest.filename(), linkPath);
                } catch (...) {
                    copyFileOverwrite(dest, linkPath);
                }
            }
        }
    }
    writeQtConfIfNeeded(plan);
}

void copyPluginsELF(const ResolveContext& ctx, const DeployPlan& plan) {
    if (ctx.qt.qtInstallPlugins.empty()) return;
    const fs::path src = ctx.qt.qtInstallPlugins;
    fs::path platformSo = src / "platforms" / "libqxcb.so";
    if (fs::exists(platformSo)) copyFileOverwrite(platformSo, plan.outputRoot / "usr" / "plugins" / "platforms" / platformSo.filename());
    for (const char* name : {"libqjpeg.so","libqico.so","libqgif.so","libqpng.so"}) {
        fs::path p = src / "imageformats" / name;
        if (fs::exists(p)) copyFileOverwrite(p, plan.outputRoot / "usr" / "plugins" / "imageformats" / p.filename());
    }
    int code = 0;
    std::string pluginsDir = (plan.outputRoot / "usr" / "plugins").string();
    std::string cmd = std::string("find ") + shellEscape(pluginsDir) + " -type f -name '*.so*' -exec patchelf --set-rpath '$ORIGIN/../../lib' {} +";
    runCommand(cmd, code);
}

void copyMainAndPatchELF(const DeployPlan& plan) {
    fs::path dest = plan.outputRoot / "usr" / "bin" / plan.binaryPath.filename();
    if (!copyFileOverwrite(plan.binaryPath, dest)) {
        std::cerr << "Warning: failed to copy main binary: " << plan.binaryPath << " -> " << dest << "\n";
        return;
    }
    int code = 0;
    std::string cmd = std::string("patchelf --set-rpath '$ORIGIN/../lib' ") + shellEscape(dest.string());
    runCommand(cmd, code);
    if (code != 0) {
        std::cerr << "Warning: patchelf failed to set RUNPATH on " << dest << "\n";
    }
}

void copyResolvedForMachO(const DeployPlan& plan, const std::vector<fs::path>& libs) {
    fs::path fwDir = plan.outputRoot / "Contents" / "Frameworks";
    std::error_code ec;
    fs::create_directories(fwDir, ec);
    std::unordered_set<std::string> copiedFrameworks;
    for (const auto& lib : libs) {
        if (isVerbose()) std::cout << "[macho-copy] lib: " << lib << "\n";
        fs::path frameworkRoot;
        fs::path cur = lib.parent_path();
        while (!cur.empty() && cur.has_parent_path()) {
            if (cur.extension() == ".framework") { frameworkRoot = cur; break; }
            cur = cur.parent_path();
        }
        if (!frameworkRoot.empty()) {
            fs::path dst = fwDir / frameworkRoot.filename();
            std::string key = frameworkRoot.filename().string();
            if (!copiedFrameworks.count(key)) {
                copiedFrameworks.insert(key);
                if (isVerbose()) std::cout << "[macho-copy] framework: " << frameworkRoot << " -> " << dst << "\n";
                fs::copy(frameworkRoot, dst, fs::copy_options::recursive | fs::copy_options::overwrite_existing | fs::copy_options::skip_symlinks, ec);
                if (ec) {
                    std::cerr << "Warning: failed to copy framework " << frameworkRoot << " -> " << dst << ": " << ec.message() << "\n";
                }
            }
        } else {
            fs::path dest = fwDir / lib.filename();
            if (isVerbose()) std::cout << "[macho-copy] dylib: " << lib << " -> " << dest << "\n";
            if (!copyFileOverwrite(lib, dest)) {
                std::cerr << "Warning: failed to copy " << lib << " -> " << dest << "\n";
            }
        }
    }
}

void copyPluginsMachO(const ResolveContext& ctx, const DeployPlan& plan) {
    if (ctx.qt.qtInstallPlugins.empty()) return;
    const fs::path src = ctx.qt.qtInstallPlugins;
    fs::path dstBase = plan.outputRoot / "Contents" / "PlugIns";
    fs::path cocoa = src / "platforms" / "libqcocoa.dylib";
    if (fs::exists(cocoa)) copyFileOverwrite(cocoa, dstBase / "platforms" / cocoa.filename());
    for (const char* name : {"libqjpeg.dylib","libqico.dylib","libqgif.dylib","libqpng.dylib"}) {
        fs::path p = src / "imageformats" / name;
        if (fs::exists(p)) copyFileOverwrite(p, dstBase / "imageformats" / p.filename());
    }
    std::error_code ec;
    if (fs::exists(dstBase, ec)) {
        for (auto it = fs::recursive_directory_iterator(dstBase, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec) && it->path().extension() == ".dylib") {
                int code = 0;
                std::string cmd = std::string("llvm-install-name-tool -add_rpath '@loader_path/../../Frameworks' ") + shellEscape(it->path().string());
                runCommand(cmd, code);
            }
        }
    }
}

void copyMainAndPatchMachO(const DeployPlan& plan) {
    fs::path macOSDir = plan.outputRoot / "Contents" / "MacOS";
    std::error_code ec;
    fs::create_directories(macOSDir, ec);
    fs::path dest = macOSDir / plan.binaryPath.filename();
    if (!copyFileOverwrite(plan.binaryPath, dest)) {
        std::cerr << "Warning: failed to copy main binary: " << plan.binaryPath << " -> " << dest << "\n";
        return;
    }
    int code = 0;
    std::string cmd = std::string("llvm-install-name-tool -add_rpath '@executable_path/../Frameworks' ") + shellEscape(dest.string());
    runCommand(cmd, code);
    if (code != 0) {
        std::cerr << "Warning: llvm-install-name-tool failed to add rpath on " << dest << "\n";
    }
}

void copyMainPE(const DeployPlan& plan) {
    fs::path dest = plan.outputRoot / plan.binaryPath.filename();
    if (!copyFileOverwrite(plan.binaryPath, dest)) {
        std::cerr << "Warning: failed to copy main binary: " << plan.binaryPath << " -> " << dest << "\n";
    }
}

} // namespace cdqt


